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

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
)

// TagPair 索引维度键值对（前端表格产出格式，值支持模板）。
type TagPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// FieldPair 字段映射：Key 为落盘字段名，Source 为采集点 name。
type FieldPair struct {
	Key    string `json:"key"`
	Source string `json:"source"`
}

// AcquisitionMapping 采集点数组 → SeriesPoint 的可选映射配置。
// 各落盘组件嵌入此结构：配置 Measurement 后可直接接收 x/iotRead 输出的点数组并透视落盘，
// 无需上游再接转换节点；不配置则输入须为 SeriesPoint 格式（向后兼容）。
type AcquisitionMapping struct {
	Measurement string      `json:"measurement" label:"Measurement" desc:"测点表名，支持 ${msg.xx}/${metadata.xx}；配置后输入按采集点数组透视"`
	Tags        []TagPair   `json:"tags" label:"Tags" desc:"索引维度键值对，值支持模板"`
	Fields      []FieldPair `json:"fields" label:"Fields" desc:"字段映射 key->采集点name，用于筛选/重命名；为空则全量展开所有点"`
}

// Enabled 是否启用采集数据映射。
func (m AcquisitionMapping) Enabled() bool {
	return m.Measurement != ""
}

// MapData 把采集点数组透视为单个 SeriesPoint 的 JSON。
// 启用且输入为点数组时返回 (新数据, true)；否则返回 (原数据, false)，调用方按原样处理。
func (m AcquisitionMapping) MapData(data string, env map[string]interface{}) (string, bool) {
	if !m.Enabled() {
		return data, false
	}
	var datas []iot_points.Data
	if err := json.Unmarshal([]byte(data), &datas); err != nil || len(datas) == 0 {
		return data, false
	}
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
		return data, false
	}
	fields := m.resolveFields(byName)
	if len(fields) == 0 {
		return data, false
	}
	tags := make(map[string]string, len(m.Tags))
	for _, tp := range m.Tags {
		if tp.Key == "" {
			continue
		}
		tags[tp.Key] = iot_points.RenderTemplate(tp.Value, env)
	}
	sp := SeriesPoint{
		Measurement: iot_points.RenderTemplate(m.Measurement, env),
		Tags:        tags,
		Fields:      fields,
		Timestamp:   ts,
	}
	b, err := json.Marshal([]SeriesPoint{sp})
	if err != nil {
		return data, false
	}
	return string(b), true
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
