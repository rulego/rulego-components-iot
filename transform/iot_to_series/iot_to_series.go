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

// Package iot_to_series 把扁平 map（或 map 数组）转换为 tsdb.SeriesPoint 列表，
// 衔接流式聚合（x/streamAggregator）等 map 形态上游与下游时序写入（x/tsdbWrite）。
package iot_to_series

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&Node{})
}

// Configuration 定义测点映射：measurement/tags 支持 ${msg.xx}/${metadata.xx} 模板。
type Configuration struct {
	Measurement    string            `json:"measurement" label:"Measurement" desc:"measurement name, supports ${msg.xx}/${metadata.xx}" required:"true"`
	Tags           map[string]string `json:"tags" label:"Tags" desc:"tag key -> value template, e.g. {\"deviceId\":\"${metadata.deviceId}\"}"`
	Fields         map[string]string `json:"fields" label:"Fields" desc:"field key -> source key; empty = use entire msg.Data as fields"`
	TimestampField string            `json:"timestampField" label:"Timestamp Field" desc:"field holding unix ns timestamp; empty = now"`
}

// Node 把 msg.Data 转为 []SeriesPoint 写回 msg.Data（JSON）。
type Node struct {
	Config Configuration
}

func (x *Node) New() types.Node {
	return &Node{Config: Configuration{Measurement: "iot_data"}}
}

func (x *Node) Type() string {
	return "x/iotToSeries"
}

func (x *Node) Init(ruleConfig types.Config, configuration types.Configuration) error {
	return maps.Map2Struct(configuration, &x.Config)
}

func (x *Node) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rows, err := parseRows(msg.GetData())
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	measurement := iot_points.RenderTemplate(x.Config.Measurement, env)
	tags := renderTags(x.Config.Tags, env)
	points := make([]tsdb.SeriesPoint, 0, len(rows))
	for _, row := range rows {
		points = append(points, tsdb.SeriesPoint{
			Measurement: measurement,
			Tags:        tags,
			Fields:      resolveFields(x.Config.Fields, row),
			Timestamp:   resolveTimestamp(x.Config.TimestampField, row),
		})
	}
	data, _ := json.Marshal(points)
	msg.DataType = types.JSON
	msg.SetData(string(data))
	ctx.TellSuccess(msg)
}

// parseRows 把 msg.Data 解析为 map 行列表（单对象或数组）。
func parseRows(data string) ([]map[string]interface{}, error) {
	if data == "" {
		return nil, fmt.Errorf("empty msg.Data")
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal([]byte(data), &rows); err == nil && len(rows) > 0 {
		return rows, nil
	}
	var row map[string]interface{}
	if err := json.Unmarshal([]byte(data), &row); err != nil {
		return nil, fmt.Errorf("msg.Data must be JSON object or array: %w", err)
	}
	return []map[string]interface{}{row}, nil
}

// renderTags 渲染 tag 值模板。
func renderTags(config map[string]string, env map[string]interface{}) map[string]string {
	if len(config) == 0 {
		return nil
	}
	out := make(map[string]string, len(config))
	for k, v := range config {
		out[k] = iot_points.RenderTemplate(v, env)
	}
	return out
}

// resolveFields 解析字段映射：配置为空时整个 row 作为 fields，否则按 {fieldKey: sourceKey} 提取。
func resolveFields(config map[string]string, row map[string]interface{}) map[string]interface{} {
	if len(config) == 0 {
		return row
	}
	out := make(map[string]interface{}, len(config))
	for fk, sk := range config {
		// 缺失 source key 时跳过，避免写入 nil 字段（对齐 tsdb.AcquisitionMapping）
		if v, ok := row[sk]; ok {
			out[fk] = v
		}
	}
	return out
}

// resolveTimestamp 解析时间戳：优先取指定字段（ns），缺省用当前时间。
func resolveTimestamp(field string, row map[string]interface{}) int64 {
	if field == "" {
		return time.Now().UnixNano()
	}
	switch v := row[field].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			return ts
		}
	}
	return time.Now().UnixNano()
}

func (x *Node) Destroy() {}

func (x *Node) Desc() string {
	return "Convert msg.Data (map or array) to tsdb.SeriesPoint list for downstream tsdb write."
}
