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

package iot_points

import (
	"errors"
	"testing"

	"github.com/rulego/rulego/api/types"
	"github.com/stretchr/testify/assert"
)

type testPoint struct {
	Name string `json:"name"`
}

func TestRenderTemplate(t *testing.T) {
	env := map[string]interface{}{
		"msg": map[string]interface{}{"name": "temp"},
	}
	assert.Equal(t, "plain", RenderTemplate("plain", env))      // 不含 ${ 原样返回
	assert.Equal(t, "", RenderTemplate("", env))                // 空串
	assert.Equal(t, "temp", RenderTemplate("${msg.name}", env)) // 渲染
	assert.Equal(t, "plain", RenderTemplate("plain", nil))      // nil env 不 panic
}

func TestResolvePoints(t *testing.T) {
	config := []testPoint{{Name: "config"}}
	sentinel := errors.New("empty")
	newMsg := func(data string) types.RuleMsg {
		return types.NewMsg(0, "test", types.JSON, types.NewMetadata(), data)
	}

	// msg.Data 带点位 -> 优先 msg
	pts, err := ResolvePoints(config, newMsg(`[{"name":"dyn"}]`), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "dyn", pts[0].Name)

	// msg.Data 空 -> 用配置
	pts2, err := ResolvePoints(config, newMsg(""), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "config", pts2[0].Name)

	// 都空 -> emptyErr
	_, err = ResolvePoints[testPoint](nil, newMsg(""), sentinel)
	assert.Equal(t, sentinel, err)

	// 都空且 emptyErr=nil -> 默认错误
	_, err = ResolvePoints[testPoint](nil, newMsg(""), nil)
	assert.NotNil(t, err)

	// msg.Data 非法 JSON -> 回退配置
	pts3, err := ResolvePoints(config, newMsg("not-json"), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "config", pts3[0].Name)

	// msg.Data = null/[] -> 用配置
	pts4, err := ResolvePoints(config, newMsg("null"), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "config", pts4[0].Name)
	pts5, err := ResolvePoints(config, newMsg("[]"), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "config", pts5[0].Name)
}
