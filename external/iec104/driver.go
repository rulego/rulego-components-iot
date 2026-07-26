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

package iec104

import (
	"fmt"
	"strconv"
	"strings"

	iec104client "github.com/rulego/rulego-components-iot/pkg/iec104_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/wendy512/go-iecp5/asdu"
)

// driver 适配 iot_points.Driver 到 IEC 104 client。
type driver struct {
	client *iec104client.Client
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *iec104client.Client) *driver {
	return &driver{client: client}
}

// ReadPoints 总召唤批量采集。无效 IOA 单点标记 Error 不参与召唤；
// 子站未上送(quality=bad)标记 Error 与真实空值区分；client 层全失败才返回 error。
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, 0, len(points))
	cp := make([]iec104client.Point, 0, len(points))
	slots := make([]int, 0, len(points)) // cp 各点在 out 中的下标
	for _, p := range points {
		ip, err := toIec104Point(p)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			continue
		}
		cp = append(cp, ip)
		slots = append(slots, len(out))
		out = append(out, iot_points.Data{Name: p.Name})
	}
	if len(cp) == 0 {
		if len(points) > 0 {
			return nil, fmt.Errorf("all %d iec104 points have invalid IOA", len(points))
		}
		return out, nil
	}
	datas, err := d.client.ReadPoints(cp)
	if err != nil {
		return nil, err
	}
	for j, dd := range datas {
		if j >= len(slots) {
			break
		}
		slot := &out[slots[j]]
		if dd.Quality == "bad" {
			slot.Error = "no data from substation (quality=bad)"
			continue
		}
		slot.Value = dd.Value
		slot.Timestamp = dd.Timestamp.UnixNano()
	}
	return out, nil
}

// WritePoints 逐点下发遥控/遥调命令。Type 指定命令类型,value 为命令值。
func (d *driver) WritePoints(points []iot_points.Point) error {
	for _, p := range points {
		ioa, err := strconv.ParseUint(strings.TrimSpace(p.Addr), 10, 32)
		if err != nil {
			return fmt.Errorf("iec104: invalid IOA %q for point %s: %w", p.Addr, p.Name, err)
		}
		typeId, value, err := parseControlCmd(p)
		if err != nil {
			return fmt.Errorf("iec104: point %s: %w", p.Name, err)
		}
		if err := d.client.SendControlCmd(typeId, uint(ioa), value); err != nil {
			return fmt.Errorf("iec104: send control to IOA %s (%s) failed: %w", p.Addr, p.Name, err)
		}
	}
	return nil
}

// parseControlCmd 解析点位 Type+Value 为命令类型标识和命令值。
func parseControlCmd(p iot_points.Point) (asdu.TypeID, any, error) {
	switch strings.ToUpper(strings.TrimSpace(p.Type)) {
	case "C_SC_NA_1", "SINGLE", "BOOL":
		v := strings.EqualFold(strings.TrimSpace(p.Value), "true") || p.Value == "1"
		return asdu.C_SC_NA_1, v, nil
	case "C_DC_NA_1", "DOUBLE":
		n, err := strconv.ParseUint(strings.TrimSpace(p.Value), 10, 8)
		if err != nil {
			return 0, nil, fmt.Errorf("double command value %q: expect 1(on) or 2(off)", p.Value)
		}
		return asdu.C_DC_NA_1, uint8(n), nil
	case "C_SE_NB_1", "SCALED", "INT16":
		n, err := strconv.ParseInt(strings.TrimSpace(p.Value), 10, 16)
		if err != nil {
			return 0, nil, fmt.Errorf("scaled setpoint value %q: %w", p.Value, err)
		}
		return asdu.C_SE_NB_1, int16(n), nil
	case "C_SE_NC_1", "FLOAT", "FLOAT32":
		f, err := strconv.ParseFloat(strings.TrimSpace(p.Value), 32)
		if err != nil {
			return 0, nil, fmt.Errorf("float setpoint value %q: %w", p.Value, err)
		}
		return asdu.C_SE_NC_1, float32(f), nil
	default:
		return 0, nil, fmt.Errorf("unsupported control type %q (expect C_SC_NA_1/C_DC_NA_1/C_SE_NB_1/C_SE_NC_1)", p.Type)
	}
}

// toIec104Point 把统一 Point(Addr=信息体地址 IOA)映射为 iec104client.Point。
func toIec104Point(p iot_points.Point) (iec104client.Point, error) {
	ioa, err := strconv.ParseUint(strings.TrimSpace(p.Addr), 10, 32)
	if err != nil {
		return iec104client.Point{}, fmt.Errorf("invalid iec104 IOA %q: %w", p.Addr, err)
	}
	return iec104client.Point{
		Name: p.Name,
		Ioa:  uint(ioa),
		Type: p.Type,
	}, nil
}
