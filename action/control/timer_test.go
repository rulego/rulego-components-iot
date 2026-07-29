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

// emit 一次下游输出的快照。
type emit struct {
	rel  string
	data string
	q    string
}

// collector 收集回调输出,供异步定时断言使用。
type collector struct {
	ch chan emit
}

func newCollector() *collector {
	return &collector{ch: make(chan emit, 64)}
}

func (c *collector) callback() func(msg types.RuleMsg, relationType string, err error) {
	return func(msg types.RuleMsg, relationType string, err error) {
		q := ""
		if msg.Metadata != nil {
			q = msg.Metadata.GetValue("q")
		}
		c.ch <- emit{rel: relationType, data: msg.GetData(), q: q}
	}
}

// drain 收集 d 时间窗口内到达的全部输出。
func (c *collector) drain(d time.Duration) []emit {
	var got []emit
	deadline := time.After(d)
	for {
		select {
		case o := <-c.ch:
			got = append(got, o)
		case <-deadline:
			return got
		}
	}
}

func newTimer(mode, pt, in string) types.Node {
	node := (&TimerNode{}).New()
	_ = node.Init(types.NewConfig(), types.Configuration{"mode": mode, "pt": pt, "in": in, "out": "q"})
	return node
}

func boolMsg(v string) test.Msg {
	return test.Msg{MetaData: types.BuildMetadata(map[string]string{"start": v}), Data: "{}"}
}

func TestTimerBasics(t *testing.T) {
	n := (&TimerNode{}).New()
	assert.Equal(t, "x/control/timer", n.Type())
	tn := n.(*TimerNode)
	assert.Equal(t, "TON", tn.Config.Mode)
	assert.Equal(t, "1s", tn.Config.PT)
	assert.Equal(t, "q", tn.Config.Out)
}

func TestTimerInitValidation(t *testing.T) {
	n := (&TimerNode{}).New()
	err := n.Init(types.NewConfig(), types.Configuration{"mode": "BAD", "pt": "1s"})
	assert.NotNil(t, err)

	err = n.Init(types.NewConfig(), types.Configuration{"mode": "TOF", "pt": "1s"})
	assert.Nil(t, err)
	assert.Equal(t, "q", n.(*TimerNode).Config.Out) // 默认输出键
}

// TON:输入持续 true 达 PT → q 置 true。
func TestTimerTONCommit(t *testing.T) {
	node := newTimer("TON", "80ms", "${metadata.start}")
	c := newCollector()
	test.NodeOnMsg(t, node, []test.Msg{boolMsg("true")}, c.callback())
	got := c.drain(500 * time.Millisecond)

	assert.GreaterOrEqual(t, len(got), 2)
	assert.Equal(t, types.Success, got[0].rel)
	assert.Equal(t, "false", got[0].q) // 上升沿:先输出 false 并开始计时
	sawTrue := false
	for _, o := range got {
		if o.rel == types.Success && o.q == "true" {
			sawTrue = true
		}
	}
	assert.True(t, sawTrue, "定时到点应提交 q=true")
}

// TON:输入在 PT 内变 false → 取消,永不置 true。
func TestTimerTONCancel(t *testing.T) {
	node := newTimer("TON", "200ms", "${metadata.start}")
	c := newCollector()
	test.NodeOnMsg(t, node, []test.Msg{
		{MetaData: types.BuildMetadata(map[string]string{"start": "true"}), Data: "{}", AfterSleep: 60 * time.Millisecond},
		boolMsg("false"),
	}, c.callback())
	got := c.drain(500 * time.Millisecond)

	for _, o := range got {
		assert.NotEqual(t, "true", o.q, "已取消,不应出现 q=true")
	}
}

// TOF:输入 true 立即 q=true;变 false 后延时 PT 才 q=false。
func TestTimerTOFCommit(t *testing.T) {
	node := newTimer("TOF", "80ms", "${metadata.start}")
	c := newCollector()
	test.NodeOnMsg(t, node, []test.Msg{
		{MetaData: types.BuildMetadata(map[string]string{"start": "true"}), Data: "{}", AfterSleep: 30 * time.Millisecond},
		boolMsg("false"),
	}, c.callback())
	got := c.drain(500 * time.Millisecond)

	sawTrue, sawFalse := false, false
	for _, o := range got {
		if o.q == "true" {
			sawTrue = true
		}
		if o.q == "false" {
			sawFalse = true
		}
	}
	assert.True(t, sawTrue, "上升沿应立即 q=true")
	assert.True(t, sawFalse, "下降沿延时后应 q=false")
	// 最后一次输出应为 false
	assert.Equal(t, "false", got[len(got)-1].q)
}

// In 留空时取 msg.Data 原始内容判真假。
func TestTimerRawDataInput(t *testing.T) {
	node := newTimer("TON", "80ms", "")
	c := newCollector()
	test.NodeOnMsg(t, node, []test.Msg{{Data: "true"}}, c.callback())
	got := c.drain(500 * time.Millisecond)

	sawTrue := false
	for _, o := range got {
		if o.q == "true" {
			sawTrue = true
		}
	}
	assert.True(t, sawTrue)
}
