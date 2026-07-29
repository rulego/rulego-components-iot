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
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/stretchr/testify/assert"
)

func newWatchdog(timeout, failsafe string) types.Node {
	node := (&WatchdogNode{}).New()
	_ = node.Init(types.NewConfig(), types.Configuration{"timeout": timeout, "failsafe": failsafe})
	return node
}

func TestWatchdogBasics(t *testing.T) {
	n := (&WatchdogNode{}).New()
	assert.Equal(t, "x/control/watchdog", n.Type())
	assert.Equal(t, "10s", n.(*WatchdogNode).Config.Timeout)
}

func TestWatchdogInit(t *testing.T) {
	n := (&WatchdogNode{}).New()
	// 缺 failsafe → 报错
	err := n.Init(types.NewConfig(), types.Configuration{"timeout": "1s"})
	assert.NotNil(t, err)

	// 静态 timeout 预解析
	err = n.Init(types.NewConfig(), types.Configuration{"timeout": "2s", "failsafe": "{}"})
	assert.Nil(t, err)
	assert.Equal(t, int64(2000), n.(*WatchdogNode).staticTimeoutMs)

	// 模板 timeout → -1(每次渲染)
	err = n.Init(types.NewConfig(), types.Configuration{"timeout": "${metadata.to}", "failsafe": "{}"})
	assert.Nil(t, err)
	assert.Equal(t, int64(-1), n.(*WatchdogNode).staticTimeoutMs)
}

// 正常透传:消息原样下发。
func TestWatchdogPassthrough(t *testing.T) {
	node := newWatchdog("300ms", `{"valve":0}`)
	c := newCollector()
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{"valve":1}`}}, c.callback())
	got := c.drain(120 * time.Millisecond) // 短于超时,只看透传

	assert.GreaterOrEqual(t, len(got), 1)
	assert.Equal(t, types.Success, got[0].rel)
	assert.Equal(t, `{"valve":1}`, got[0].data)
}

// 失联触发:超时未喂狗 → 下发故障安全值。
func TestWatchdogTrip(t *testing.T) {
	node := newWatchdog("100ms", `{"valve":0}`)
	c := newCollector()
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{"valve":1}`}}, c.callback())
	got := c.drain(500 * time.Millisecond)

	sawFailsafe := false
	for _, o := range got {
		if o.data == `{"valve":0}` {
			sawFailsafe = true
		}
	}
	assert.True(t, sawFailsafe, "超时后应下发故障安全值")
}

// 重新武装:窗口内持续喂狗 → 不触发。
func TestWatchdogReArm(t *testing.T) {
	node := newWatchdog("400ms", `{"valve":0}`)
	c := newCollector()
	test.NodeOnMsg(t, node, []test.Msg{
		{Data: `{"valve":1}`, AfterSleep: 50 * time.Millisecond},
		{Data: `{"valve":1}`, AfterSleep: 50 * time.Millisecond},
		{Data: `{"valve":1}`},
	}, c.callback())
	// NodeOnMsg 约 100ms 返回;最后喂狗在 ~100ms,其超时触发在 ~500ms。
	// drain 250ms 窗口约覆盖 [100,350]ms,早于触发点,期间不应出现故障安全。
	got := c.drain(250 * time.Millisecond)

	passthrough, failsafe := 0, 0
	for _, o := range got {
		if o.data == `{"valve":1}` {
			passthrough++
		}
		if o.data == `{"valve":0}` {
			failsafe++
		}
	}
	assert.Equal(t, 3, passthrough)
	assert.Equal(t, 0, failsafe, "持续喂狗不应触发故障安全")
}
