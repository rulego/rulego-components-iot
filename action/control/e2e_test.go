/*
 * Copyright 2026 The RuleGo Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package control

// End-to-end rule chain test: connect x/control/timer, x/control/watchdog to real rule engine (rulego.New),
// record all downstream outputs via custom sink node (including TellSelf delayed-commit spontaneous message), verify various timing scenarios.
// Refer to rulego/engine/engine_test.go for chain building and message feeding.
//
// Note: timer/watchdog calls TellSuccess on both business path and timer commit (one input may produce multiple outputs),
// so feeding uses async OnMsg + interval sleep to guarantee edge order, assertions use polling to avoid OnMsgAndWait completion count interfering with multiple outputs.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const e2ePT = "200ms" // unified timing duration for end-to-end tests

// ---- output recorder (isolated by subtest gen, preventing delayed alarms from previous subtest interfering with next) ----

type recEntry struct {
	gen  int64
	q    string // timer output (metadata.q)
	data string // message body (watchdog pass-through / failsafe value)
}

var (
	recMu  sync.Mutex
	recs   []recEntry
	recGen int64
)

func nextGen() int64 { return atomic.AddInt64(&recGen, 1) }

func recsFor(gen int64) []recEntry {
	recMu.Lock()
	defer recMu.Unlock()
	var out []recEntry
	for _, r := range recs {
		if r.gen == gen {
			out = append(out, r)
		}
	}
	return out
}

func hasQ(gen int64, v string) bool {
	for _, r := range recsFor(gen) {
		if r.q == v {
			return true
		}
	}
	return false
}

func countQ(gen int64, v string) int {
	n := 0
	for _, r := range recsFor(gen) {
		if r.q == v {
			n++
		}
	}
	return n
}

func hasData(gen int64, v string) bool {
	for _, r := range recsFor(gen) {
		if r.data == v {
			return true
		}
	}
	return false
}

// waitFor polls until cond is true (for "will eventually happen after delay" assertions).
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// ---- custom sink node: records every message flowing through it ----

type controlSink struct{}

func (*controlSink) Type() string    { return "test/controlSink" }
func (*controlSink) New() types.Node { return &controlSink{} }
func (*controlSink) Init(types.Config, types.Configuration) error {
	return nil
}
func (*controlSink) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	q := ""
	if msg.Metadata != nil {
		q = msg.Metadata.GetValue("q")
	}
	recMu.Lock()
	recs = append(recs, recEntry{gen: atomic.LoadInt64(&recGen), q: q, data: msg.GetData()})
	recMu.Unlock()
	ctx.TellSuccess(msg)
}
func (*controlSink) Destroy() {}

func init() { _ = rulego.Registry.Register(&controlSink{}) }

// ---- message feeding helpers ----

// startMsg builds an input message with metadata.start (simulating start signal read by cyclic scan).
func startMsg(v string) types.RuleMsg {
	md := types.NewMetadata()
	md.PutValue("start", v)
	return types.NewMsg(0, "SCAN", types.JSON, md, "{}")
}

// dataMsg builds a message with data body (simulating setpoint/heartbeat from host).
func dataMsg(d string) types.RuleMsg {
	return types.NewMsg(0, "DATA", types.JSON, types.NewMetadata(), d)
}

// ---- chain building helpers ----

func newTimerChain(t *testing.T, id, mode string) types.RuleEngine {
	dsl := fmt.Sprintf(`{
	  "ruleChain":{"id":"%s","root":true},
	  "metadata":{"nodes":[
	    {"id":"t","type":"x/control/timer","configuration":{"mode":"%s","pt":"%s","in":"${metadata.start}","out":"q"}},
	    {"id":"sink","type":"test/controlSink","configuration":{}}
	  ],"connections":[{"fromId":"t","toId":"sink","type":"Success"}]}
	}`, id, mode, e2ePT)
	rg, err := rulego.New(id, []byte(dsl), engine.WithConfig(rulego.NewConfig(types.WithDefaultPool())))
	require.NoError(t, err, "create timer chain")
	// Remove from the global DefaultPool on subtest end. RuleEngine.Stop does not delete its own entry,
	// so a fixed id reused in a later -count run would hit the stopped engine and silently drop messages.
	t.Cleanup(func() { rulego.Del(id) })
	return rg
}

func newWatchdogChain(t *testing.T, id, timeout, failsafe string) types.RuleEngine {
	dsl := fmt.Sprintf(`{
	  "ruleChain":{"id":"%s","root":true},
	  "metadata":{"nodes":[
	    {"id":"wd","type":"x/control/watchdog","configuration":{"timeout":"%s","failsafe":"%s"}},
	    {"id":"sink","type":"test/controlSink","configuration":{}}
	  ],"connections":[{"fromId":"wd","toId":"sink","type":"Success"}]}
	}`, id, timeout, failsafe)
	rg, err := rulego.New(id, []byte(dsl), engine.WithConfig(rulego.NewConfig(types.WithDefaultPool())))
	require.NoError(t, err, "create watchdog chain")
	t.Cleanup(func() { rulego.Del(id) })
	return rg
}

// settle is the subtest end wait, ensuring all delayed alarms of this subtest have fired (within its own gen) and do not interfere with subsequent subtests.
const settle = 350 * time.Millisecond

// feed asynchronously feeds one message and waits briefly; the sleep usually lets the message finish processing before the next feed, but is not a strict ordering guarantee.
func feed(rg types.RuleEngine, msg types.RuleMsg) {
	rg.OnMsg(msg)
	time.Sleep(50 * time.Millisecond)
}

// ---- Timer end-to-end ----

func TestControlE2E_TimerTON(t *testing.T) {
	t.Run("commit_assert_on_continuous_on", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_commit", "TON")

		feed(rg, startMsg("true")) // rising edge: output q=false and start timing
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "true") }),
			"Should commit q=true after input stays on for PT duration")

		rs := recsFor(gen)
		require.NotEmpty(t, rs)
		assert.Equal(t, "false", rs[0].q, "Should output false on rising edge first")
		time.Sleep(settle)
	})

	t.Run("cancel_abort_on_mid_off", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_cancel", "TON")

		feed(rg, startMsg("true"))  // rising edge, arm
		feed(rg, startMsg("false")) // falling edge within PT -> cancel
		time.Sleep(500 * time.Millisecond)

		assert.False(t, hasQ(gen, "true"), "Cancelled, expired alarm should be discarded, no q=true")
		time.Sleep(settle)
	})

	t.Run("retrigger_rearm_after_reset", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_retrigger", "TON")

		feed(rg, startMsg("true")) // first rising edge
		assert.True(t, waitFor(time.Second, func() bool { return countQ(gen, "true") >= 1 }), "Should assert q=true on first trigger")

		feed(rg, startMsg("false")) // reset
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "false") }), "Should reset q=false on falling edge")

		feed(rg, startMsg("true")) // second rising edge, re-arm
		assert.True(t, waitFor(time.Second, func() bool { return countQ(gen, "true") >= 2 }), "Should assert q=true on second trigger")
		time.Sleep(settle)
	})

	t.Run("cancel_no_block_and_normal_finish", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_cancel_no_block", "TON")

		ended := make(chan struct{}, 4)
		onEnd := types.WithOnAllNodeCompleted(func() { ended <- struct{}{} })
		// Process the rising edge synchronously first; otherwise back-to-back async submits can let the
		// pool process the falling edge first (a no-op on the initial in=false), leaving the timer armed
		// with no subsequent cancel, so the alarm fires q=true.
		rg.OnMsgAndWait(startMsg("true"))  // rising edge, arm
		rg.OnMsg(startMsg("false"), onEnd) // falling edge within PT, cancel

		// The cancel execution should complete within the time limit, otherwise considered blocked
		select {
		case <-ended:
		case <-time.After(2 * time.Second):
			t.Fatal("Cancel caused rule chain to not finish normally (suspected block)")
		}
		time.Sleep(300 * time.Millisecond)
		assert.False(t, hasQ(gen, "true"), "Cancelled, should not have q=true")
		time.Sleep(settle)
	})
}

func TestControlE2E_TimerTOF(t *testing.T) {
	t.Run("commit_reset_on_continuous_off", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "tof_commit", "TOF")

		feed(rg, startMsg("true")) // rising edge: TOF immediately outputs q=true
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "true") }), "Should assert q=true immediately on rising edge")

		feed(rg, startMsg("false")) // falling edge: start timing, q temporarily keeps true
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "false") }),
			"Should commit q=false after input stays off for PT duration")
		time.Sleep(settle)
	})

	t.Run("cancel_abort_on_mid_on", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "tof_cancel", "TOF")

		feed(rg, startMsg("true"))  // q=true
		feed(rg, startMsg("false")) // falling edge, arm
		feed(rg, startMsg("true"))  // rising edge within PT -> cancel and reset
		time.Sleep(500 * time.Millisecond)

		assert.False(t, hasQ(gen, "false"), "Cancelled, should not have q=false")
		time.Sleep(settle)
	})
}

// ---- Watchdog end-to-end ----

func TestControlE2E_Watchdog(t *testing.T) {
	const failsafe = `{\"v\":0}` // failsafe JSON escaped in DSL, parses to {"v":0}

	t.Run("trip_fail_safe_on_disconnect", func(t *testing.T) {
		gen := nextGen()
		rg := newWatchdogChain(t, "wd_trip", e2ePT, failsafe)

		feed(rg, dataMsg(`{"v":1}`))      // feed dog: pass-through {"v":1}
		assert.True(t, hasData(gen, `{"v":1}`), "Normal message should pass through")
		time.Sleep(500 * time.Millisecond) // timeout without feeding again

		assert.True(t, waitFor(time.Second, func() bool { return hasData(gen, `{"v":0}`) }),
			"Should issue fail-safe value after timeout")
		time.Sleep(settle)
	})

	t.Run("rearm_no_trip_on_continuous_feed", func(t *testing.T) {
		gen := nextGen()
		rg := newWatchdogChain(t, "wd_rearm", "300ms", failsafe)

		// interval (50ms) much less than timeout (300ms), feed dog 4 times consecutively
		feed(rg, dataMsg(`{"v":1}`))
		feed(rg, dataMsg(`{"v":1}`))
		feed(rg, dataMsg(`{"v":1}`))
		feed(rg, dataMsg(`{"v":1}`))
		time.Sleep(100 * time.Millisecond) // still within timeout window of last feed

		passthrough := 0
		for _, r := range recsFor(gen) {
			if r.data == `{"v":1}` {
				passthrough++
			}
		}
		assert.Equal(t, 4, passthrough, "Each feed should pass through exactly one, no duplication")
		assert.False(t, hasData(gen, `{"v":0}`), "Continuous feeding should not trigger fail-safe")
		time.Sleep(settle)
	})
}
