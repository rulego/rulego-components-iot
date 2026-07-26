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

// Package iot_points 提供 IoT 采集组件共享的点位解析与模板渲染。
package iot_points

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/el"
)

// RenderTemplate 渲染 ${msg.xx}/${metadata.xx} 模板变量；不含 ${ 或解析失败时原样返回。
func RenderTemplate(s string, env map[string]interface{}) string {
	if s == "" || !strings.Contains(s, "${") {
		return s
	}
	t, err := el.NewTemplate(s)
	if err != nil {
		return s
	}
	return t.ExecuteAsString(env)
}

// ResolvePoints 解析点位来源：msg.Data 合法点位优先，否则用配置 points；两者皆空返回 emptyErr。
func ResolvePoints[P any](configPoints []P, msg types.RuleMsg, emptyErr error) ([]P, error) {
	if data := strings.TrimSpace(msg.GetData()); data != "" && data != "null" && data != "[]" {
		var msgPoints []P
		if err := json.Unmarshal([]byte(data), &msgPoints); err == nil && len(msgPoints) > 0 {
			return msgPoints, nil
		}
	}
	if len(configPoints) == 0 {
		if emptyErr == nil {
			return nil, errors.New("no points: configure points or pass [{...}] via msg.Data")
		}
		return nil, emptyErr
	}
	return configPoints, nil
}
