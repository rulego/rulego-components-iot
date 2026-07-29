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

// 端到端规则链测试：把 x/control/timer、x/control/watchdog 接入真实规则引擎（rulego.New），
// 通过自定义 sink 节点记录全部下游输出（含 TellSelf 延时提交那条自发消息），验证各种时序情况。
// 参考 rulego/engine/engine_test.go 的建链与喂消息方式。
//
// 说明：timer/watchdog 在业务路径与定时提交都会 TellSuccess（一条输入可能产生多次输出），
// 故喂消息用异步 OnMsg + 间隔 sleep 保证边沿顺序，断言用轮询，避免 OnMsgAndWait 的完成计数与多次输出相互干扰。

import (
	"context"
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

const e2ePT = "200ms" // 端到端测试统一定时时长

// ---- 输出记录器（按子测试 gen 隔离，防止前一个子测试的延迟闹钟串扰后一个）----

type recEntry struct {
	gen  int64
	q    string // timer 输出（metadata.q）
	data string // 消息体（watchdog 透传/故障安全值）
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

// waitFor 轮询等待 cond 成立（用于"延时后终将发生"的断言）。
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

// ---- 自定义 sink 节点：记录流经它的每条消息 ----

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

// ---- 喂消息辅助 ----

// startMsg 构造带 metadata.start 的输入消息（模拟周期扫描读到的启动信号）。
func startMsg(v string) types.RuleMsg {
	md := types.NewMetadata()
	md.PutValue("start", v)
	return types.NewMsg(0, "SCAN", types.JSON, md, "{}")
}

// dataMsg 构造带数据体的消息（模拟上位机下发的设定值/心跳）。
func dataMsg(d string) types.RuleMsg {
	return types.NewMsg(0, "DATA", types.JSON, types.NewMetadata(), d)
}

// ---- 建链辅助 ----

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
	return rg
}

// settle 子测试结尾等待，确保本子测试的所有延迟闹钟都已触发（落在自己的 gen 内），不串扰后续子测试。
const settle = 350 * time.Millisecond

// feed 异步喂一条消息并等待其被处理，保证边沿顺序确定。
func feed(rg types.RuleEngine, msg types.RuleMsg) {
	rg.OnMsg(msg)
	time.Sleep(50 * time.Millisecond)
}

// ---- Timer 端到端 ----

func TestControlE2E_TimerTON(t *testing.T) {
	t.Run("commit_持续接通则置位", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_commit", "TON")
		defer rg.Stop(context.Background())

		feed(rg, startMsg("true")) // 上升沿：输出 q=false 并开始计时
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "true") }),
			"输入持续到达 PT 后应提交 q=true")

		rs := recsFor(gen)
		require.NotEmpty(t, rs)
		assert.Equal(t, "false", rs[0].q, "上升沿当拍应先输出 false")
		time.Sleep(settle)
	})

	t.Run("cancel_中途断开则取消", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_cancel", "TON")
		defer rg.Stop(context.Background())

		feed(rg, startMsg("true"))  // 上升沿，武装
		feed(rg, startMsg("false")) // PT 内下降沿 → 取消
		time.Sleep(500 * time.Millisecond)

		assert.False(t, hasQ(gen, "true"), "已取消，过期闹钟应被丢弃，不应出现 q=true")
		time.Sleep(settle)
	})

	t.Run("retrigger_复位后重新触发", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_retrigger", "TON")
		defer rg.Stop(context.Background())

		feed(rg, startMsg("true")) // 第一次上升沿
		assert.True(t, waitFor(time.Second, func() bool { return countQ(gen, "true") >= 1 }), "第一次应置位")

		feed(rg, startMsg("false")) // 复位
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "false") }), "下降沿应复位 q=false")

		feed(rg, startMsg("true")) // 第二次上升沿，重新武装
		assert.True(t, waitFor(time.Second, func() bool { return countQ(gen, "true") >= 2 }), "应第二次置位 q=true")
		time.Sleep(settle)
	})

	t.Run("cancel_取消不阻塞且执行正常结束", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "ton_cancel_no_block", "TON")
		defer rg.Stop(context.Background())

		// 每条消息用 WithOnAllNodeCompleted 标记该次执行结束；取消不应导致执行无法结束（阻塞）
		ended := make(chan struct{}, 4)
		onEnd := types.WithOnAllNodeCompleted(func() { ended <- struct{}{} })
		rg.OnMsg(startMsg("true"), onEnd)  // 上升沿，武装
		rg.OnMsg(startMsg("false"), onEnd) // PT 内下降沿，取消

		// 两次执行都应在限定时间内结束，否则视为阻塞
		for i := 0; i < 2; i++ {
			select {
			case <-ended:
			case <-time.After(2 * time.Second):
				t.Fatal("取消导致规则链未正常结束（疑似阻塞）")
			}
		}
		time.Sleep(300 * time.Millisecond)
		assert.False(t, hasQ(gen, "true"), "已取消，不应出现 q=true")
		time.Sleep(settle)
	})
}

func TestControlE2E_TimerTOF(t *testing.T) {
	t.Run("commit_持续断开则复位", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "tof_commit", "TOF")
		defer rg.Stop(context.Background())

		feed(rg, startMsg("true")) // 上升沿：TOF 立即输出 q=true
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "true") }), "上升沿应立即 q=true")

		feed(rg, startMsg("false")) // 下降沿：开始计时，q 暂保持 true
		assert.True(t, waitFor(time.Second, func() bool { return hasQ(gen, "false") }),
			"输入持续断开到达 PT 后应提交 q=false")
		time.Sleep(settle)
	})

	t.Run("cancel_中途接通则取消", func(t *testing.T) {
		gen := nextGen()
		rg := newTimerChain(t, "tof_cancel", "TOF")
		defer rg.Stop(context.Background())

		feed(rg, startMsg("true"))  // q=true
		feed(rg, startMsg("false")) // 下降沿，武装
		feed(rg, startMsg("true"))  // PT 内上升沿 → 取消复位
		time.Sleep(500 * time.Millisecond)

		assert.False(t, hasQ(gen, "false"), "已取消，不应出现 q=false")
		time.Sleep(settle)
	})
}

// ---- Watchdog 端到端 ----

func TestControlE2E_Watchdog(t *testing.T) {
	const failsafe = `{\"v\":0}` // DSL 内转义的故障安全 JSON，解析后为 {"v":0}

	t.Run("trip_失联则下发故障安全", func(t *testing.T) {
		gen := nextGen()
		rg := newWatchdogChain(t, "wd_trip", e2ePT, failsafe)
		defer rg.Stop(context.Background())

		feed(rg, dataMsg(`{"v":1}`))      // 喂狗：透传 {"v":1}
		assert.True(t, hasData(gen, `{"v":1}`), "正常消息应透传")
		time.Sleep(500 * time.Millisecond) // 超时未再喂狗

		assert.True(t, waitFor(time.Second, func() bool { return hasData(gen, `{"v":0}`) }),
			"超时后应下发故障安全值")
		time.Sleep(settle)
	})

	t.Run("rearm_持续喂狗则不触发", func(t *testing.T) {
		gen := nextGen()
		rg := newWatchdogChain(t, "wd_rearm", "300ms", failsafe)
		defer rg.Stop(context.Background())

		// 间隔(50ms)远小于超时(300ms)连续喂狗 4 次
		feed(rg, dataMsg(`{"v":1}`))
		feed(rg, dataMsg(`{"v":1}`))
		feed(rg, dataMsg(`{"v":1}`))
		feed(rg, dataMsg(`{"v":1}`))
		time.Sleep(100 * time.Millisecond) // 仍在最后一次喂狗的超时窗口内

		passthrough := 0
		for _, r := range recsFor(gen) {
			if r.data == `{"v":1}` {
				passthrough++
			}
		}
		assert.Equal(t, 4, passthrough, "每次喂狗应恰好透传一条，不应重复")
		assert.False(t, hasData(gen, `{"v":0}`), "持续喂狗不应触发故障安全")
		time.Sleep(settle)
	})
}
