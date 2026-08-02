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

// Package iot_points provides IoT acquisition component shared point parsing and template rendering.
package iot_points

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/el"
)

// RenderTemplate renders ${msg.xx}/${metadata.xx} template variables; returns as-is when no ${} or parsing fails.
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

// ResolvePoints resolves point source: msg.Data valid points take priority, otherwise use configured points; both empty returns emptyErr.
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
