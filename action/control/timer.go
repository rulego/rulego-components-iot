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

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// timerAlarmMsgType internal alarm message type, used in OnMsg to distinguish "timer expiry callback" from "business input".
const timerAlarmMsgType = "CONTROL_TIMER_ALARM"

// timerCommitMsgType message type for reinjection after alarm expiry for passthrough (via new ctx).
const timerCommitMsgType = "CONTROL_TIMER_COMMIT"

func init() {
	_ = rulego.Registry.Register(&TimerNode{})
}

// TimerConfig soft-PLC timer configuration.
type TimerConfig struct {
	Mode string `json:"mode" label:"Mode" desc:"TON(on-delay: output true after input held true for PT) / TOF(off-delay: output false after input held false for PT)" required:"true"`
	PT   string `json:"pt" label:"PresetTime" desc:"preset duration, e.g. 3s / 500ms, supports ${metadata.xx}" required:"true"`
	In   string `json:"in" label:"Input" desc:"boolean input template, e.g. ${metadata.start}; empty = interpret raw msg.Data as boolean"`
	Out  string `json:"out" label:"OutputKey" desc:"metadata key to write the boolean output, default q"`
}

// TimerNode soft-PLC timer (TON/TOF). Cancelable, retriggerable: uses generation count to invalidate old alarms.
// Each business input forwards current q; rising/falling edge arms timer by mode, commits q on expiry.
type TimerNode struct {
	Config TimerConfig
	mu     sync.Mutex
	in     bool   // Previous scan input
	q      bool   // Current output
	gen    uint64 // Generation: increments on input edge, invalidates pending timers
}

func (x *TimerNode) New() types.Node {
	return &TimerNode{Config: TimerConfig{Mode: "TON", PT: "1s", Out: "q"}}
}

func (x *TimerNode) Type() string { return "x/control/timer" }

func (x *TimerNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	if x.Config.Out == "" {
		x.Config.Out = "q"
	}
	if x.Config.Mode != "TON" && x.Config.Mode != "TOF" {
		return fmt.Errorf("x/control/timer: mode must be TON or TOF, got %q", x.Config.Mode)
	}
	return nil
}

func (x *TimerNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	switch msg.Type {
	case timerAlarmMsgType:
		x.onAlarm(ctx, msg)
		return
	case timerCommitMsgType:
		// A newer edge may have changed q after this commit was scheduled but before it is
		// dispatched; re-validate under lock and drop the stale output to avoid a flip.
		if committed, err := strconv.ParseBool(msg.Metadata.GetValue(x.Config.Out)); err == nil {
			x.mu.Lock()
			stale := committed != x.q
			x.mu.Unlock()
			if stale {
				return
			}
		}
		ctx.TellSuccess(msg)
		return
	}
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	ptMs, err := parseDurationMs(iot_points.RenderTemplate(x.Config.PT, env))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	newIn := x.readInput(env, msg)

	x.mu.Lock()
	edge := newIn != x.in
	x.in = newIn
	var g uint64
	schedule := false
	if x.Config.Mode == "TON" {
		switch {
		case edge && newIn: // Rising edge: arm delay, set to true on timeout
			x.gen++
			if ptMs <= 0 {
				x.q = true
			} else {
				g, schedule = x.gen, true
			}
		case edge && !newIn: // Falling edge: cancel, immediately set to false
			x.gen++
			x.q = false
		}
	} else { // TOF
		switch {
		case edge && newIn: // Rising edge: cancel, immediately set to true
			x.gen++
			x.q = true
		case edge && !newIn: // Falling edge: arm delay, set to false on timeout
			x.gen++
			if ptMs <= 0 {
				x.q = false
			} else {
				g, schedule = x.gen, true
			}
		}
	}
	q := x.q
	x.mu.Unlock()

// First output current q, and prepare independent copy for alarm (modify copy, not original msg).
// TellSuccess asynchronously dispatches to downstream, after forwarding no longer modify msg to avoid race with downstream concurrent reads.
	msg.Metadata.PutValue(x.Config.Out, strconv.FormatBool(q))
	var alarmMsg types.RuleMsg
	if schedule {
		alarmMsg = msg.Copy()
		alarmMsg.Type = timerAlarmMsgType
		alarmMsg.Metadata.PutValue(genKey, strconv.FormatUint(g, 10))
	}
	ctx.TellSuccess(msg)
	if schedule {
		ctx.TellSelf(alarmMsg, ptMs)
	}
}

// onAlarm timer expiry: only commit target q when generation not invalidated by new edge.
func (x *TimerNode) onAlarm(ctx types.RuleContext, msg types.RuleMsg) {
	g, _ := strconv.ParseUint(msg.Metadata.GetValue(genKey), 10, 64)
	x.mu.Lock()
	if g != x.gen {
		x.mu.Unlock()
		return // Already cancelled by new edge
	}
	x.q = x.targetQ()
	q := x.q
	x.mu.Unlock()

// Reinject commit message via new ctx then passthrough, avoid data race from reusing same ctx with business dispatch of kick message
	msg.Metadata.PutValue(x.Config.Out, strconv.FormatBool(q))
	msg.Type = timerCommitMsgType
	ctx.TellNode(context.Background(), ctx.GetSelfId(), msg, false, nil, nil)
}

// targetQ target output on timer commit: TON delays to true, TOF delays to false.
func (x *TimerNode) targetQ() bool { return x.Config.Mode == "TON" }

// readInput parses boolean input: if In is configured, use template; otherwise use msg.Data raw content to determine true/false.
func (x *TimerNode) readInput(env map[string]interface{}, msg types.RuleMsg) bool {
	if x.Config.In == "" {
		return toBool(msg.GetData())
	}
	return toBool(iot_points.RenderTemplate(x.Config.In, env))
}

func (x *TimerNode) Destroy() {}

func (x *TimerNode) Desc() string {
	return "Soft-PLC timer (TON on-delay / TOF off-delay), cancellable and retriggerable. Writes boolean output to metadata[Out] (default q). Routes to Success/Failure."
}
