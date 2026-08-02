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
	"strings"
	"sync"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// watchdogAlarmMsgType internal timeout check message type.
const watchdogAlarmMsgType = "CONTROL_WATCHDOG_ALARM"

// watchdogFailsafeMsgType message type for reinjection after timeout trigger for failsafe value passthrough (via new ctx).
const watchdogFailsafeMsgType = "CONTROL_WATCHDOG_FAILSAFE"

func init() {
	_ = rulego.Registry.Register(&WatchdogNode{})
}

// WatchdogConfig watchdog configuration.
type WatchdogConfig struct {
	Timeout  string `json:"timeout" label:"Timeout" desc:"kick timeout, e.g. 10s; if no message arrives within this window the failsafe is emitted, supports ${metadata.xx}" required:"true"`
	Failsafe string `json:"failsafe" label:"Failsafe" desc:"JSON emitted downstream on timeout, e.g. {\"valve\":0,\"motor\":0}" required:"true"`
}

// WatchdogNode soft-PLC watchdog: protocol/data shape agnostic. Each message passes through and re-arms;
// If no message received within timeout, emit failsafe value. Uses generation count to distinguish "re-armed" from "expired check".
type WatchdogNode struct {
	Config          WatchdogConfig
	mu              sync.Mutex
	gen             uint64
	staticTimeoutMs int64 // -1 = timeout contains template, needs rendering each time
}

func (x *WatchdogNode) New() types.Node {
	return &WatchdogNode{Config: WatchdogConfig{Timeout: "10s"}, staticTimeoutMs: -1}
}

func (x *WatchdogNode) Type() string { return "x/control/watchdog" }

func (x *WatchdogNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	if strings.TrimSpace(x.Config.Failsafe) == "" {
		return fmt.Errorf("x/control/watchdog: failsafe is required")
	}
	x.staticTimeoutMs = -1
	if !strings.Contains(x.Config.Timeout, "${") {
		ms, err := parseDurationMs(x.Config.Timeout)
		if err != nil {
			return err
		}
		x.staticTimeoutMs = ms
	}
	return nil
}

func (x *WatchdogNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	switch msg.Type {
	case watchdogAlarmMsgType:
		x.onAlarm(ctx, msg)
		return
	case watchdogFailsafeMsgType:
		ctx.TellSuccess(msg) // Failsafe message pass-through (from fresh ctx), no re-arm
		return
	}
	timeoutMs, err := x.resolveTimeout(ctx, msg)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	x.mu.Lock()
	x.gen++
	g := x.gen
	x.mu.Unlock()

// First prepare independent copy for timeout check (modify copy, not original msg). TellSuccess asynchronously dispatches to downstream,
// After passthrough, no longer modify msg to avoid race condition with downstream concurrent reads.
	var alarmMsg types.RuleMsg
	if timeoutMs > 0 {
		alarmMsg = msg.Copy()
		alarmMsg.Type = watchdogAlarmMsgType
		alarmMsg.Metadata.PutValue(genKey, strconv.FormatUint(g, 10))
	}
	ctx.TellSuccess(msg)
	if timeoutMs > 0 {
		ctx.TellSelf(alarmMsg, timeoutMs)
	}
}

// onAlarm timeout check expiry: only emit failsafe value when generation not invalidated by new feed.
func (x *WatchdogNode) onAlarm(ctx types.RuleContext, msg types.RuleMsg) {
	g, _ := strconv.ParseUint(msg.Metadata.GetValue(genKey), 10, 64)
	x.mu.Lock()
	if g != x.gen {
		x.mu.Unlock()
		return // Fed during period, re-arm
	}
	x.mu.Unlock()

// Reinject failsafe message via new ctx then passthrough, avoid data race from reusing same ctx with business dispatch of kick message
	failsafe := types.NewMsgWithJsonData(x.Config.Failsafe)
	failsafe.Type = watchdogFailsafeMsgType
	ctx.TellNode(context.Background(), ctx.GetSelfId(), failsafe, false, nil, nil)
}

func (x *WatchdogNode) resolveTimeout(ctx types.RuleContext, msg types.RuleMsg) (int64, error) {
	if x.staticTimeoutMs >= 0 {
		return x.staticTimeoutMs, nil
	}
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	return parseDurationMs(iot_points.RenderTemplate(x.Config.Timeout, env))
}

func (x *WatchdogNode) Destroy() {}

func (x *WatchdogNode) Desc() string {
	return "Soft-PLC watchdog. Passes each message through and re-arms; if no message arrives within Timeout, emits the failsafe JSON downstream. Routes to Success/Failure."
}
