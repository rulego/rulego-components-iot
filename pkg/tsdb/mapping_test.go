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

// TestMapDataFullExpand expands all acquisition points when fields not configured
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
	assert.False(t, hasBad) // Bad points filtered out
}

// TestMapDataFieldsMapping filters and renames by key->source when fields configured
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
	assert.Equal(t, 25.3, points[0].Fields["temp_c"])      // Renaming effective
	assert.Equal(t, float64(60), points[0].Fields["humi_pct"])
	_, hasPressure := points[0].Fields["pressure"]
	assert.False(t, hasPressure) // Unconfigured points filtered out
	_, hasOldName := points[0].Fields["temperature"]
	assert.False(t, hasOldName) // Original point name no longer used as field name
}

// TestMapDataFieldsMappingMiss ignores field when source does not match any point
func TestMapDataFieldsMappingMiss(t *testing.T) {
	m := AcquisitionMapping{
		Measurement: "dev",
		Fields:      []FieldPair{{Key: "x", Source: "not_exist"}},
	}
	data := `[{"name":"temperature","value":25.3}]`
	// When fields configured but none match, fields empty -> do not map, pass through as-is
	out, ok := m.MapData(data, nil)
	assert.False(t, ok)
	assert.Equal(t, data, out)
}

// TestMapDataFlatMap flat map input, entire map as fields generates SeriesPoint
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

// TestMapDataFlatMapArray flat map array, generates SeriesPoint per row
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

// TestMapDataFlatMapTimestampReserved flat map 的数字 timestamp 是保留键：提取为时间戳、不进 fields
func TestMapDataFlatMapTimestampReserved(t *testing.T) {
	m := AcquisitionMapping{Measurement: "agg"}
	data := `{"avg_temp":25.3,"timestamp":1000000000}`
	out, ok := m.MapData(data, nil)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 1, len(points))
	assert.Equal(t, int64(1000000000), points[0].Timestamp, "数字 timestamp 应作为时间戳")
	assert.Equal(t, 25.3, points[0].Fields["avg_temp"])
	_, hasTs := points[0].Fields["timestamp"]
	assert.False(t, hasTs, "timestamp 提取后不应进 fields")
}

// TestMapDataFlatMapNonNumericTimestamp 非数字 timestamp 维持当字段、时间戳取写入时刻
func TestMapDataFlatMapNonNumericTimestamp(t *testing.T) {
	m := AcquisitionMapping{Measurement: "agg"}
	data := `{"avg_temp":25.3,"timestamp":"2026-08-04T12:00:00Z"}`
	out, ok := m.MapData(data, nil)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 1, len(points))
	assert.Equal(t, "2026-08-04T12:00:00Z", points[0].Fields["timestamp"], "非数字 timestamp 维持当字段")
	assert.True(t, points[0].Timestamp > 0, "无数字 timestamp 时取写入时刻")
}

// TestMapDataFlatMapArrayAggregationResult 聚合结果形态（window_id + 自动注入 timestamp）落盘
func TestMapDataFlatMapArrayAggregationResult(t *testing.T) {
	m := AcquisitionMapping{Measurement: "dev_minute"}
	data := `[{"avg_voltage":225,"avg_current":5.5,"window_id":"0_1000000000","timestamp":1000000000}]`
	out, ok := m.MapData(data, nil)
	assert.True(t, ok)

	var points []SeriesPoint
	assert.Nil(t, json.Unmarshal([]byte(out), &points))
	assert.Equal(t, 1, len(points))
	assert.Equal(t, int64(1000000000), points[0].Timestamp, "用聚合结果的窗口时间戳")
	assert.Equal(t, float64(225), points[0].Fields["avg_voltage"])
	assert.Equal(t, 5.5, points[0].Fields["avg_current"])
	_, hasTs := points[0].Fields["timestamp"]
	assert.False(t, hasTs, "timestamp 提取后不进 fields")
	_, hasWindowID := points[0].Fields["window_id"]
	assert.False(t, hasWindowID, "window_id 是内部去重标识，不应落盘")
}

// TestMapDataSeriesPointPassthrough does not double-map when already SeriesPoint shape
func TestMapDataSeriesPointPassthrough(t *testing.T) {
	m := AcquisitionMapping{Measurement: "dev"}
	data := `[{"measurement":"dev","tags":{"d":"1"},"fields":{"temp":25},"timestamp":123}]`
	out, ok := m.MapData(data, nil)
	assert.False(t, ok)
	assert.Equal(t, data, out)
}

// TestMapDataNotEnabled passes through directly when measurement not configured
func TestMapDataNotEnabled(t *testing.T) {
	m := AcquisitionMapping{}
	data := `{"temperature":25}`
	out, ok := m.MapData(data, nil)
	assert.False(t, ok)
	assert.Equal(t, data, out)
}

// TestMapDataFlatMapWithFields flat map + Fields configuration: filters/renames by key->source
func TestMapDataFlatMapWithFields(t *testing.T) {
	m := AcquisitionMapping{
		Measurement: "sensor",
		Fields: []FieldPair{
			{Key: "temperature", Source: "temperature"},
			{Key: "humidity", Source: "humidity"},
		},
	}
	// deviceId not in Fields configuration, should be filtered out
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
