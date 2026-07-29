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

// timerAlarmMsgType 内部闹钟消息类型,用于在 OnMsg 里区分"定时到期回调"与"业务输入"。
const timerAlarmMsgType = "CONTROL_TIMER_ALARM"

// timerCommitMsgType 闹钟到点提交后重新注入、用于透传的消息类型（走全新 ctx）。
const timerCommitMsgType = "CONTROL_TIMER_COMMIT"

func init() {
	_ = rulego.Registry.Register(&TimerNode{})
}

// TimerConfig 软 PLC 定时器配置。
type TimerConfig struct {
	Mode string `json:"mode" label:"Mode" desc:"TON(on-delay: output true after input held true for PT) / TOF(off-delay: output false after input held false for PT)" required:"true"`
	PT   string `json:"pt" label:"PresetTime" desc:"preset duration, e.g. 3s / 500ms, supports ${metadata.xx}" required:"true"`
	In   string `json:"in" label:"Input" desc:"boolean input template, e.g. ${metadata.start}; empty = interpret raw msg.Data as boolean"`
	Out  string `json:"out" label:"OutputKey" desc:"metadata key to write the boolean output, default q"`
}

// TimerNode 软 PLC 定时器(TON/TOF)。可取消、可重触发:用代次计数作废旧闹钟。
// 每次业务输入都按当前 q 转发;上升/下降沿按模式武装定时,到点提交 q。
type TimerNode struct {
	Config TimerConfig
	mu     sync.Mutex
	in     bool   // 上一扫描输入
	q      bool   // 当前输出
	gen    uint64 // 代次:输入边沿自增,作废在途闹钟
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
		ctx.TellSuccess(msg) // 闹钟提交消息透传（来自全新 ctx）
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
		case edge && newIn: // 上升沿:武装延时,到点置 true
			x.gen++
			if ptMs <= 0 {
				x.q = true
			} else {
				g, schedule = x.gen, true
			}
		case edge && !newIn: // 下降沿:取消,立即置 false
			x.gen++
			x.q = false
		}
	} else { // TOF
		switch {
		case edge && newIn: // 上升沿:取消,立即置 true
			x.gen++
			x.q = true
		case edge && !newIn: // 下降沿:武装延时,到点置 false
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

	// 先输出当前 q，并为闹钟准备独立副本（改副本而非原 msg）。
	// TellSuccess 异步派发到下游，转发后不再修改 msg，避免与下游并发读取竞态。
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

// onAlarm 定时到期:仅当代次未被新边沿作废时提交目标 q。
func (x *TimerNode) onAlarm(ctx types.RuleContext, msg types.RuleMsg) {
	g, _ := strconv.ParseUint(msg.Metadata.GetValue(genKey), 10, 64)
	x.mu.Lock()
	if g != x.gen {
		x.mu.Unlock()
		return // 已被新边沿取消
	}
	x.q = x.targetQ()
	q := x.q
	x.mu.Unlock()

	// 经全新 ctx 重新注入提交消息再透传，避免与踢消息的业务派发复用同一 ctx 产生数据竞争
	msg.Metadata.PutValue(x.Config.Out, strconv.FormatBool(q))
	msg.Type = timerCommitMsgType
	ctx.TellNode(context.Background(), ctx.GetSelfId(), msg, false, nil, nil)
}

// targetQ 定时提交的目标输出:TON 延时到置 true,TOF 延时到置 false。
func (x *TimerNode) targetQ() bool { return x.Config.Mode == "TON" }

// readInput 解析布尔输入:配了 In 走模板,否则取 msg.Data 原始内容判真假。
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
