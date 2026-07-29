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

// 定时器的时序行为（延时提交、中途取消、重触发、TOF）由 e2e_test.go 通过真实规则引擎覆盖；
// 这里只测不依赖引擎的基础行为。

import (
	"testing"

	"github.com/rulego/rulego/api/types"
	"github.com/stretchr/testify/assert"
)

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
