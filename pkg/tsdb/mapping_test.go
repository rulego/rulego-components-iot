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

// TestMapDataFlatMap 扁平 map 输入，整个 map 作为 fields 生成 SeriesPoint。
func TestMapDataFlatMap(t *testing.T) {
	m := AcquisitionMapping{
		Measurement: "sensor",
		Tags:        []TagPair{{Key: "device", Value: "${metadata.deviceId}"}},
	}
	data := `{"temperature":25.3,"humidity":60}`
	env := map[string]interface{}{"metadata": map[string]interface{}{"deviceId": "dev-01"}}
	out, ok := m.MapData(data, env)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 1, len(points))
	assert.Equal(t, "sensor", points[0].Measurement)
	assert.Equal(t, "dev-01", points[0].Tags["device"])
	assert.Equal(t, 25.3, points[0].Fields["temperature"])
	assert.Equal(t, float64(60), points[0].Fields["humidity"])
	assert.True(t, points[0].Timestamp > 0)
}

// TestMapDataFlatMapArray 扁平 map 数组，逐行生成 SeriesPoint。
func TestMapDataFlatMapArray(t *testing.T) {
	m := AcquisitionMapping{Measurement: "agg"}
	data := `[{"avg_temp":25.3,"max_humi":80},{"avg_temp":26.1,"max_humi":75}]`
	out, ok := m.MapData(data, nil)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 2, len(points))
	assert.Equal(t, 25.3, points[0].Fields["avg_temp"])
	assert.Equal(t, 26.1, points[1].Fields["avg_temp"])
	assert.Equal(t, "agg", points[0].Measurement)
	assert.Equal(t, "agg", points[1].Measurement)
}

// TestMapDataSeriesPointPassthrough 已经是 SeriesPoint 形状时不二次映射。
func TestMapDataSeriesPointPassthrough(t *testing.T) {
	m := AcquisitionMapping{Measurement: "dev"}
	data := `[{"measurement":"dev","tags":{"d":"1"},"fields":{"temp":25},"timestamp":123}]`
	out, ok := m.MapData(data, nil)
	assert.False(t, ok)
	assert.Equal(t, data, out)
}

// TestMapDataNotEnabled 未配置 measurement 时直接透传。
func TestMapDataNotEnabled(t *testing.T) {
	m := AcquisitionMapping{}
	data := `{"temperature":25}`
	out, ok := m.MapData(data, nil)
	assert.False(t, ok)
	assert.Equal(t, data, out)
}

// TestMapDataFlatMapWithFields 扁平 map + Fields 配置：按 key->source 筛选/重命名。
func TestMapDataFlatMapWithFields(t *testing.T) {
	m := AcquisitionMapping{
		Measurement: "sensor",
		Fields: []FieldPair{
			{Key: "temperature", Source: "temperature"},
			{Key: "humidity", Source: "humidity"},
		},
	}
	// deviceId 不在 Fields 配置中，应被过滤掉
	data := `{"deviceId":"dev-07","temperature":25.6,"humidity":60.5}`
	out, ok := m.MapData(data, nil)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 1, len(points))
	assert.Equal(t, 25.6, points[0].Fields["temperature"])
	assert.Equal(t, 60.5, points[0].Fields["humidity"])
	_, hasDeviceId := points[0].Fields["deviceId"]
	assert.False(t, hasDeviceId)
}
