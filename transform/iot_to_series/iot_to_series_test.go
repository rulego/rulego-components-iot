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

package iot_to_series

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRows(t *testing.T) {
	// 单对象
	rows, err := parseRows(`{"温度":25.6}`)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(rows))
	assert.Equal(t, 25.6, rows[0]["温度"])

	// 数组
	rows, err = parseRows(`[{"a":1},{"a":2}]`)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(rows))

	// 非法
	_, err = parseRows("not-json")
	assert.NotNil(t, err)
	// 空
	_, err = parseRows("")
	assert.NotNil(t, err)
}

func TestResolveFields(t *testing.T) {
	row := map[string]interface{}{"温度": 25.6, "压力": 101.3, "extra": "x"}

	// 空 -> 整个 row
	f := resolveFields(nil, row)
	assert.Equal(t, 25.6, f["温度"])
	assert.Equal(t, "x", f["extra"])

	// 映射 -> 提取子集并重命名
	f = resolveFields(map[string]string{"temp": "温度"}, row)
	assert.Equal(t, 25.6, f["temp"])
	_, ok := f["压力"]
	assert.False(t, ok)
}

func TestResolveTimestamp(t *testing.T) {
	// 缺省字段 -> now
	ts := resolveTimestamp("", map[string]interface{}{})
	assert.NotEqual(t, int64(0), ts)

	// float64（JSON 数字）
	ts = resolveTimestamp("ts", map[string]interface{}{"ts": float64(1700000000000000000)})
	assert.Equal(t, int64(1700000000000000000), ts)

	// 字符串数字
	ts = resolveTimestamp("ts", map[string]interface{}{"ts": "1700000000000000000"})
	assert.Equal(t, int64(1700000000000000000), ts)

	// 字段缺失 -> now
	ts = resolveTimestamp("ts", map[string]interface{}{})
	assert.NotEqual(t, int64(0), ts)
}

func TestRenderTags(t *testing.T) {
	env := map[string]interface{}{
		"msg":      map[string]interface{}{"area": "A"},
		"metadata": map[string]interface{}{"deviceId": "d1"},
	}
	tags := renderTags(map[string]string{
		"area":   "${msg.area}",
		"devId":  "${metadata.deviceId}",
		"static": "fixed",
	}, env)
	assert.Equal(t, "A", tags["area"])
	assert.Equal(t, "d1", tags["devId"])
	assert.Equal(t, "fixed", tags["static"])

	// 空 config
	assert.Nil(t, renderTags(nil, env))
}
