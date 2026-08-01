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

// TagPair 索引维度键值对（前端表格产出格式，值支持模板）。
type TagPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// FieldPair 字段映射：Key 为落盘字段名，Source 为来源键（采集点 name 或 map key）。
type FieldPair struct {
	Key    string `json:"key"`
	Source string `json:"source"`
}

// AcquisitionMapping 采集数据 → SeriesPoint 的可选映射配置。
// 各落盘组件嵌入此结构：配置 Measurement 后可直接接收采集点数组（透视合并）
// 或扁平 map/map 数组（逐行转换）并落盘，无需上游再接转换节点；
// 不配置则输入须为 SeriesPoint 格式（向后兼容）。
type AcquisitionMapping struct {
	Measurement string      `json:"measurement" label:"Measurement" desc:"测点表名，支持 ${msg.xx}/${metadata.xx}；配置后输入按采集点数组透视"`
	Tags        []TagPair   `json:"tags" label:"Tags" desc:"索引维度键值对，值支持模板"`
	Fields      []FieldPair `json:"fields" label:"Fields" desc:"字段映射 key->来源键（采集点name或map key），筛选/重命名；为空则全量展开"`
}

// Enabled 是否启用采集数据映射。
func (m AcquisitionMapping) Enabled() bool {
	return m.Measurement != ""
}

// MapData 把采集点数组或扁平 map 转换为 SeriesPoint JSON。
// 启用且输入可映射时返回 (新数据, true)；否则返回 (原数据, false)，调用方按原样处理。
//
// 示例 1 — 采集点数组透视（N 点 → 1 个 SeriesPoint）：
//
//	输入: [{"name":"temp","value":25},{"name":"humi","value":60}]
//	输出: [{"measurement":"dev","tags":{...},"fields":{"temp":25,"humi":60},"timestamp":max}]
//
// 示例 2 — 扁平 map（整个 map 作为 fields）：
//
//	输入: {"temperature":25.3,"humidity":60}
//	输出: [{"measurement":"dev","tags":{...},"fields":{"temperature":25.3,"humidity":60},"timestamp":now}]
//
// 示例 3 — 扁平 map 数组（逐行转换）：
//
//	输入: [{"avg_temp":25},{"avg_temp":26}]
//	输出: [{"measurement":"dev","fields":{"avg_temp":25},...},{"measurement":"dev","fields":{"avg_temp":26},...}]
//
// 已为 SeriesPoint 形状（含 measurement+fields 键）时不二次映射，原样透传。
func (m AcquisitionMapping) MapData(data string, env map[string]interface{}) (string, bool) {
	if !m.Enabled() {
		return data, false
	}
	// 优先：采集点数组透视（N 点 → 1 个 SeriesPoint）
	var datas []iot_points.Data
	if err := json.Unmarshal([]byte(data), &datas); err == nil && len(datas) > 0 && datas[0].Name != "" {
		if out, ok := m.mapPointArray(datas, env); ok {
			return out, true
		}
		return data, false
	}
	// 兜底：扁平 map / map 数组（每行 → 1 个 SeriesPoint）
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

// mapPointArray 采集点数组透视为单个 SeriesPoint。
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

// renderTags 渲染 TagPair 列表为 map。
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

// parseFlatRows 尝试把 data 解析为扁平 map 行列表。
// 已经是 SeriesPoint 形状（含 measurement+fields 键）时返回 nil，防止二次映射。
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

// isSeriesPointShape 判断 map 是否已为 SeriesPoint 结构。
func isSeriesPointShape(m map[string]interface{}) bool {
	_, hasMeasurement := m["measurement"]
	_, hasFields := m["fields"]
	return hasMeasurement && hasFields
}

// resolveFields 构建字段集：配置 Fields 时按 key->source 筛选/重命名，否则全量展开所有点。
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

// resolveMapFields 从扁平 map 构建字段集：配置 Fields 时按 key->source 筛选/重命名，否则整个 map 作为 fields。
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
