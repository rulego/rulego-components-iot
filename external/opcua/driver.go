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

package opcua

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
)

// driver 适配 iot_points.Driver 到 OPC UA client。无状态，持 client 引用。
type driver struct {
	client *opcua.Client
	logger types.Logger
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *opcua.Client, logger types.Logger) *driver {
	return &driver{client: client, logger: logger}
}

// ReadPoints 批量读取 NodeID（Point.Addr）。复用 opcuaClient.Read 获取 DisplayName 与值。
// 单点非 OK 标记 Error；全部失败返回 error。
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	nodeIds := make([]string, len(points))
	for i, p := range points {
		nodeIds[i] = p.Addr
	}
	data, resp, err := opcuaClient.Read(d.client, nodeIds, d.logger)
	if err != nil {
		return nil, err
	}
	out := opcuaClient.ToPointsData(points, data, resp)
	for _, dd := range out {
		if dd.Error == "" { // 至少一个点成功
			return out, nil
		}
	}
	if len(points) > 0 {
		return nil, fmt.Errorf("all %d opcua points failed (possible connection error)", len(points))
	}
	return out, nil
}

// WritePoints 批量写入 NodeID（Point.Addr 为 NodeID，Point.Value 为写入值）。
// 任一节点写入非 OK 即返回 error。
func (d *driver) WritePoints(points []iot_points.Point) error {
	nodesToWrite := make([]*ua.WriteValue, 0, len(points))
	for _, p := range points {
		id, err := ua.ParseNodeID(p.Addr)
		if err != nil {
			return fmt.Errorf("parse nodeId %q: %w", p.Addr, err)
		}
		v, err := ua.NewVariant(parseValue(p.Value, mapType(p.Type)))
		if err != nil {
			return fmt.Errorf("new variant for %q: %w", p.Addr, err)
		}
		nodesToWrite = append(nodesToWrite, &ua.WriteValue{
			NodeID:      id,
			AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        v,
			},
		})
	}
	resp, err := d.client.Write(context.Background(), &ua.WriteRequest{NodesToWrite: nodesToWrite})
	if err != nil {
		return err
	}
	var errs []string
	for _, r := range resp.Results {
		if r != ua.StatusOK {
			errs = append(errs, r.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("write failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

// resolvePoints 解析点位来源。msg.Data 优先，兼容三种格式；为空回退配置 points。
//  1. []iot_points.Point —— 新点位格式（addr=NodeID）
//  2. []string —— 旧 read 格式，nodeId 数组，如 ["ns=2;s=Temperature"]
//  3. []opcuaClient.Data —— 旧 write 格式，{nodeId,value,dataType}
func resolvePoints(configPoints []iot_points.Point, msg types.RuleMsg, emptyErr error) ([]iot_points.Point, error) {
	raw := strings.TrimSpace(msg.GetData())
	if raw != "" && raw != "null" && raw != "[]" {
		if ids, ok := decodeNodeIds(raw); ok {
			out := make([]iot_points.Point, len(ids))
			for i, id := range ids {
				out[i] = iot_points.Point{Addr: id}
			}
			return out, nil
		}
		if pts, ok := decodeObjectPoints(raw); ok {
			return pts, nil
		}
	}
	if len(configPoints) == 0 {
		if emptyErr != nil {
			return nil, emptyErr
		}
		return nil, errors.New("no opcua points: configure points or pass nodeIds/points via msg.Data")
	}
	return configPoints, nil
}

// decodeNodeIds 解析旧 read 格式（nodeId 字符串数组）。
func decodeNodeIds(raw string) ([]string, bool) {
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err == nil && len(ids) > 0 {
		return ids, true
	}
	return nil, false
}

// decodeObjectPoints 解析对象数组，按首元素键区分新 Point(addr) / 旧 Data(nodeId)。
func decodeObjectPoints(raw string) ([]iot_points.Point, bool) {
	var probe []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &probe); err != nil || len(probe) == 0 {
		return nil, false
	}
	if _, ok := probe[0]["addr"]; ok {
		var pts []iot_points.Point
		if err := json.Unmarshal([]byte(raw), &pts); err == nil && len(pts) > 0 {
			return pts, true
		}
		return nil, false
	}
	if _, ok := probe[0]["nodeId"]; ok {
		var ds []opcuaClient.Data
		if err := json.Unmarshal([]byte(raw), &ds); err == nil && len(ds) > 0 {
			return legacyDataToPoints(ds), true
		}
	}
	return nil, false
}

// legacyDataToPoints 把旧 opcuaClient.Data 转为统一 Point。
func legacyDataToPoints(ds []opcuaClient.Data) []iot_points.Point {
	out := make([]iot_points.Point, len(ds))
	for i, d := range ds {
		b, _ := json.Marshal(d.Value)
		out[i] = iot_points.Point{Addr: d.NodeId, Value: string(b), Type: d.DataType}
	}
	return out
}

// parseValue 把 Point.Value（字符串）按 opcua 类型解析为 ua.NewVariant 能接受的 Go 值。
func parseValue(value, opcuaType string) interface{} {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	var v interface{}
	if err := json.Unmarshal([]byte(value), &v); err == nil {
		return castValue(v, opcuaType)
	}
	return castValue(value, opcuaType)
}

// mapType 统一类型枚举 -> opcua 原生类型（供 castValueByType）；未知类型（如旧 dataType）透传。
func mapType(t string) string {
	switch strings.ToUpper(t) {
	case iot_points.TypeBool:
		return "boolean"
	case iot_points.TypeInt16:
		return "int16"
	case iot_points.TypeUint16:
		return "uint16"
	case iot_points.TypeInt32:
		return "int32"
	case iot_points.TypeUint32:
		return "uint32"
	case iot_points.TypeInt64:
		return "int64"
	case iot_points.TypeUint64:
		return "uint64"
	case iot_points.TypeFloat32:
		return "float"
	case iot_points.TypeFloat64:
		return "double"
	case iot_points.TypeString:
		return "string"
	default:
		return t
	}
}
