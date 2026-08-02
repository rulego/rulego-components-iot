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
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
)

// TagPair index dimension key-value pair (output format from frontend table, value supports templates)
type TagPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// FieldPair field mapping: Key is storage field name, Source is source key (acquisition point name or map key)
type FieldPair struct {
	Key    string `json:"key"`
	Source string `json:"source"`
}

// AcquisitionMapping optional mapping configuration for acquisition data -> SeriesPoint.
// Embedded by each storage component: after configuring Measurement, can directly receive acquisition point arrays (pivoted merge)
// or flat map/map arrays (row-by-row conversion) and write to storage, no need for upstream conversion nodes;
// if not configured, input must be SeriesPoint format (backward compatible).
type AcquisitionMapping struct {
	Measurement string      `json:"measurement" label:"Measurement" desc:"Measurement table name, supports ${msg.xx}/${metadata.xx}; when configured, input is pivoted by acquisition point array"`
	Tags        []TagPair   `json:"tags" label:"Tags" desc:"Index dimension key-value pairs, values support templates"`
	Fields      []FieldPair `json:"fields" label:"Fields" desc:"Field mapping key->source key (acquisition point name or map key), for filtering/renaming; if empty, expand all"`
}

// Enabled whether acquisition data mapping is enabled.
func (m AcquisitionMapping) Enabled() bool {
	return m.Measurement != ""
}

// MapData converts acquisition point arrays or flat maps to SeriesPoint JSON.
// Returns (new data, true) when enabled and input is mappable; otherwise returns (original data, false), caller processes as-is.
//
// Example 1 - Acquisition point array pivoting (N points -> 1 SeriesPoint):
//
//	Input: [{"name":"temp","value":25},{"name":"humi","value":60}]
//	Output: [{"measurement":"dev","tags":{...},"fields":{"temp":25,"humi":60},"timestamp":max}]
//
// Example 2 - Flat map (entire map as fields):
//
//	Input: {"temperature":25.3,"humidity":60}
//	Output: [{"measurement":"dev","tags":{...},"fields":{"temperature":25.3,"humidity":60},"timestamp":now}]
//
// Example 3 - Flat map array (row-by-row conversion):
//
//	Input: [{"avg_temp":25},{"avg_temp":26}]
//	Output: [{"measurement":"dev","fields":{"avg_temp":25},...},{"measurement":"dev","fields":{"avg_temp":26},...}]
//
// Already SeriesPoint shape (with measurement+fields keys) passes through without double-mapping.
func (m AcquisitionMapping) MapData(data string, env map[string]interface{}) (string, bool) {
	if !m.Enabled() {
		return data, false
	}
	// Priority: acquisition point array pivoting (N points -> 1 SeriesPoint)
	var datas []iot_points.Data
	if err := json.Unmarshal([]byte(data), &datas); err == nil && len(datas) > 0 && datas[0].Name != "" {
		if out, ok := m.mapPointArray(datas, env); ok {
			return out, true
		}
		return data, false
	}
	// Fallback: flat map / map array (each row -> 1 SeriesPoint)
	rows := parseFlatRows(data)
	if len(rows) == 0 {
		return data, false
	}
	points := make([]SeriesPoint, 0, len(rows))
	for _, row := range rows {
		fields := m.resolveMapFields(row)
		if len(fields) == 0 {
			continue
		}
		points = append(points, SeriesPoint{
			Measurement: iot_points.RenderTemplate(m.Measurement, env),
			Tags:        m.renderTags(env),
			Fields:      fields,
			Timestamp:   time.Now().UnixNano(),
		})
	}
	if len(points) == 0 {
		return data, false
	}
	b, err := json.Marshal(points)
	if err != nil {
		return data, false
	}
	return string(b), true
}

// mapPointArray pivots acquisition point array to single SeriesPoint
func (m AcquisitionMapping) mapPointArray(datas []iot_points.Data, env map[string]interface{}) (string, bool) {
	byName := make(map[string]iot_points.Data, len(datas))
	var ts int64
	for _, d := range datas {
		if d.Error != "" || d.Name == "" {
			continue
		}
		byName[d.Name] = d
		if d.Timestamp > ts {
			ts = d.Timestamp
		}
	}
	if len(byName) == 0 {
		return "", false
	}
	fields := m.resolveFields(byName)
	if len(fields) == 0 {
		return "", false
	}
	sp := SeriesPoint{
		Measurement: iot_points.RenderTemplate(m.Measurement, env),
		Tags:        m.renderTags(env),
		Fields:      fields,
		Timestamp:   ts,
	}
	b, err := json.Marshal([]SeriesPoint{sp})
	if err != nil {
		return "", false
	}
	return string(b), true
}

// renderTags renders TagPair list to map
func (m AcquisitionMapping) renderTags(env map[string]interface{}) map[string]string {
	if len(m.Tags) == 0 {
		return nil
	}
	tags := make(map[string]string, len(m.Tags))
	for _, tp := range m.Tags {
		if tp.Key == "" {
			continue
		}
		tags[tp.Key] = iot_points.RenderTemplate(tp.Value, env)
	}
	return tags
}

// parseFlatRows attempts to parse data into flat map row list.
// Returns nil when already SeriesPoint shape (with measurement+fields keys) to prevent double-mapping.
func parseFlatRows(data string) []map[string]interface{} {
	var rows []map[string]interface{}
	if err := json.Unmarshal([]byte(data), &rows); err == nil && len(rows) > 0 {
		if isSeriesPointShape(rows[0]) {
			return nil
		}
		return rows
	}
	var row map[string]interface{}
	if err := json.Unmarshal([]byte(data), &row); err == nil && len(row) > 0 {
		if isSeriesPointShape(row) {
			return nil
		}
		return []map[string]interface{}{row}
	}
	return nil
}

// isSeriesPointShape determines if map is already SeriesPoint structure
func isSeriesPointShape(m map[string]interface{}) bool {
	_, hasMeasurement := m["measurement"]
	_, hasFields := m["fields"]
	return hasMeasurement && hasFields
}

// resolveFields builds field set: when Fields configured, filters/rename by key->source; otherwise expands all points.
func (m AcquisitionMapping) resolveFields(byName map[string]iot_points.Data) map[string]interface{} {
	if len(m.Fields) == 0 {
		fields := make(map[string]interface{}, len(byName))
		for name, d := range byName {
			fields[name] = d.Value
		}
		return fields
	}
	fields := make(map[string]interface{}, len(m.Fields))
	for _, fp := range m.Fields {
		if fp.Key == "" {
			continue
		}
		if d, ok := byName[fp.Source]; ok {
			fields[fp.Key] = d.Value
		}
	}
	return fields
}

// resolveMapFields builds field set from flat map: when Fields configured, filters/rename by key->source; otherwise entire map as fields.
func (m AcquisitionMapping) resolveMapFields(row map[string]interface{}) map[string]interface{} {
	if len(m.Fields) == 0 {
		return row
	}
	fields := make(map[string]interface{}, len(m.Fields))
	for _, fp := range m.Fields {
		if fp.Key == "" {
			continue
		}
		if v, ok := row[fp.Source]; ok {
			fields[fp.Key] = v
		}
	}
	return fields
}
