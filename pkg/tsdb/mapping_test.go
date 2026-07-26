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

package tsdb

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMapDataFullExpand 未配置 fields 时全量展开所有采集点。
func TestMapDataFullExpand(t *testing.T) {
	m := AcquisitionMapping{Measurement: "dev"}
	data := `[{"name":"temperature","value":25.3},{"name":"humidity","value":60},{"name":"bad","error":"read failed"}]`
	out, ok := m.MapData(data, nil)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 1, len(points))
	assert.Equal(t, "dev", points[0].Measurement)
	assert.Equal(t, 25.3, points[0].Fields["temperature"])
	assert.Equal(t, float64(60), points[0].Fields["humidity"])
	_, hasBad := points[0].Fields["bad"]
	assert.False(t, hasBad) // 坏点被过滤
}

// TestMapDataFieldsMapping 配置 fields 时按 key->source 筛选并重命名。
func TestMapDataFieldsMapping(t *testing.T) {
	m := AcquisitionMapping{
		Measurement: "dev",
		Fields: []FieldPair{
			{Key: "temp_c", Source: "temperature"},
			{Key: "humi_pct", Source: "humidity"},
		},
	}
	data := `[{"name":"temperature","value":25.3},{"name":"humidity","value":60},{"name":"pressure","value":101}]`
	out, ok := m.MapData(data, nil)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 1, len(points))
	assert.Equal(t, 25.3, points[0].Fields["temp_c"])      // 重命名生效
	assert.Equal(t, float64(60), points[0].Fields["humi_pct"])
	_, hasPressure := points[0].Fields["pressure"]
	assert.False(t, hasPressure) // 未配置的点被筛掉
	_, hasOldName := points[0].Fields["temperature"]
	assert.False(t, hasOldName) // 原始点名不再作为字段名
}

// TestMapDataFieldsMappingMiss source 未匹配到任何点时该字段被忽略。
func TestMapDataFieldsMappingMiss(t *testing.T) {
	m := AcquisitionMapping{
		Measurement: "dev",
		Fields:      []FieldPair{{Key: "x", Source: "not_exist"}},
	}
	data := `[{"name":"temperature","value":25.3}]`
	// 配置了 fields 但无一匹配，fields 为空 -> 不映射，原样透传
	out, ok := m.MapData(data, nil)
	assert.False(t, ok)
	assert.Equal(t, data, out)
}
