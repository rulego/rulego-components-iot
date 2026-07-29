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

// watchdogAlarmMsgType 内部超时检查消息类型。
const watchdogAlarmMsgType = "CONTROL_WATCHDOG_ALARM"

// watchdogFailsafeMsgType 超时触发后重新注入、用于透传故障安全值的消息类型（走全新 ctx）。
const watchdogFailsafeMsgType = "CONTROL_WATCHDOG_FAILSAFE"

func init() {
	_ = rulego.Registry.Register(&WatchdogNode{})
}

// WatchdogConfig 看门狗配置。
type WatchdogConfig struct {
	Timeout  string `json:"timeout" label:"Timeout" desc:"kick timeout, e.g. 10s; if no message arrives within this window the failsafe is emitted, supports ${metadata.xx}" required:"true"`
	Failsafe string `json:"failsafe" label:"Failsafe" desc:"JSON emitted downstream on timeout, e.g. {\"valve\":0,\"motor\":0}" required:"true"`
}

// WatchdogNode 软 PLC 看门狗:协议/数据形状无关。每条消息透传并重新武装;
// 超时未再收到消息则下发故障安全值。用代次计数区分"已重新武装"与"过期检查"。
type WatchdogNode struct {
	Config          WatchdogConfig
	mu              sync.Mutex
	gen             uint64
	staticTimeoutMs int64 // -1 = timeout 含模板,需每次渲染
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
		ctx.TellSuccess(msg) // 故障安全消息透传（来自全新 ctx），不再武装
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

	// 先为超时检查准备独立副本（改副本而非原 msg）。TellSuccess 异步派发到下游，
	// 透传后不再修改 msg，避免与下游并发读取竞态。
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

// onAlarm 超时检查到期:仅当代次未被新喂狗作废时下发故障安全值。
func (x *WatchdogNode) onAlarm(ctx types.RuleContext, msg types.RuleMsg) {
	g, _ := strconv.ParseUint(msg.Metadata.GetValue(genKey), 10, 64)
	x.mu.Lock()
	if g != x.gen {
		x.mu.Unlock()
		return // 期间已喂狗,重新武装
	}
	x.mu.Unlock()

	// 经全新 ctx 重新注入故障安全消息再透传，避免与踢消息的业务派发复用同一 ctx 产生数据竞争
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
