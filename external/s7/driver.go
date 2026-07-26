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

package s7

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/robinson/gos7"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	s7client "github.com/rulego/rulego-components-iot/pkg/s7_client"
	"github.com/rulego/rulego/api/types"
)

// driver 适配 iot_points.Driver 到 S7 client。
type driver struct {
	handler *gos7.TCPClientHandler
	logger  types.Logger
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(handler *gos7.TCPClientHandler, logger types.Logger) *driver {
	return &driver{handler: handler, logger: logger}
}

func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	cp := make([]s7client.Point, 0, len(points))
	for _, p := range points {
		sp, err := toS7ClientPoint(p)
		if err != nil {
			return nil, err
		}
		cp = append(cp, sp)
	}
	datas, err := s7client.ReadPoints(d.handler, cp, d.logger)
	if err != nil {
		return nil, err
	}
	out := make([]iot_points.Data, 0, len(datas))
	for _, dd := range datas {
		// 单点质量坏标记 Error，与真实空值区分
		if dd.Quality == "bad" {
			out = append(out, iot_points.Data{Name: dd.Name, Error: "read failed (quality=bad)"})
			continue
		}
		out = append(out, iot_points.Data{
			Name:      dd.Name,
			Value:     dd.Value,
			Timestamp: dd.Timestamp.UnixNano(),
		})
	}
	return out, nil
}

func (d *driver) WritePoints(points []iot_points.Point) error {
	cp := make([]s7client.Point, 0, len(points))
	for _, p := range points {
		sp, err := toS7ClientPoint(p)
		if err != nil {
			return err
		}
		cp = append(cp, sp)
	}
	return s7client.WritePoints(d.handler, cp)
}

// toS7ClientPoint 把统一 Point（Addr，西门子官方语法）解析为 s7client.Point。
func toS7ClientPoint(p iot_points.Point) (s7client.Point, error) {
	area, dbNumber, address, bitOffset, isBit, err := parseAddr(p.Addr)
	if err != nil {
		return s7client.Point{}, err
	}
	t := mapType(p.Type)
	if isBit {
		t = "BOOL" // 位地址(DBX/M0.1/MX)强制 BOOL
	}
	return s7client.Point{
		Name:      p.Name,
		Area:      area,
		DbNumber:  dbNumber,
		Address:   address,
		BitOffset: bitOffset,
		Type:      t,
		Value:     p.Value,
	}, nil
}

// mapType 统一类型枚举 -> S7 原生类型；未知类型透传。
func mapType(t string) string {
	switch strings.ToUpper(t) {
	case iot_points.TypeBool:
		return "BOOL"
	case iot_points.TypeInt16:
		return "INT"
	case iot_points.TypeUint16:
		return "WORD"
	case iot_points.TypeInt32:
		return "DINT"
	case iot_points.TypeUint32:
		return "DWORD"
	case iot_points.TypeFloat32:
		return "REAL"
	case iot_points.TypeFloat64:
		return "LREAL"
	case iot_points.TypeString:
		return "STRING"
	default:
		return t
	}
}

// parseAddr 解析西门子官方地址语法：
//   - DB 区：DB<n>.<DBT><addr>[.<bit>]，DBT∈{DBX(位),DBB(字节),DBW(字),DBD(双字)}，如 DB1.DBD0、DB1.DBX0.1
//   - M/I/Q 区：<area><T?><addr>，T∈{B,W,D,X} 或位简写 byte.bit，如 MW0、MD0、M0.1、IW0
//   - 可选 % 前缀（TIA Portal 绝对地址）
//
// 位地址(DBX/X 后缀或 byte.bit 简写)返回 isBit=true，调用方据此强制 BOOL。
func parseAddr(addr string) (area string, dbNumber, address, bitOffset int, isBit bool, err error) {
	addr = strings.TrimSpace(strings.TrimPrefix(addr, "%"))
	if addr == "" {
		return "", 0, 0, 0, false, fmt.Errorf("empty s7 addr")
	}
	upper := strings.ToUpper(addr)
	// DB 区：DB<n>.DBT<addr>
	if strings.HasPrefix(upper, "DB") && len(addr) > 2 && addr[2] >= '0' && addr[2] <= '9' {
		rest := addr[2:]
		dot := strings.Index(rest, ".")
		if dot < 0 {
			return "", 0, 0, 0, false, fmt.Errorf("invalid DB addr %q, expect DB<n>.DBT<addr>", addr)
		}
		if dbNumber, err = strconv.Atoi(rest[:dot]); err != nil {
			return "", 0, 0, 0, false, fmt.Errorf("invalid dbNumber in %q", addr)
		}
		tail := rest[dot+1:] // DBT<addr>[.<bit>]
		if len(tail) < 4 {   // DBT(3) + addr(>=1)
			return "", 0, 0, 0, false, fmt.Errorf("invalid DB addr %q, expect DBT<addr>", addr)
		}
		switch strings.ToUpper(tail[:3]) {
		case "DBX":
			isBit = true
		case "DBB", "DBW", "DBD":
			// 存储大小由 Type 决定
		default:
			return "", 0, 0, 0, false, fmt.Errorf("unknown DB type %q in %q", tail[:3], addr)
		}
		address, bitOffset, err = parseAddrTail(tail[3:], isBit)
		if err != nil {
			return "", 0, 0, 0, false, err
		}
		return "DB", dbNumber, address, bitOffset, isBit, nil
	}
	// M/I/Q 区
	switch upper[0] {
	case 'M':
		area = "M"
	case 'I':
		area = "I"
	case 'Q':
		area = "Q"
	default:
		return "", 0, 0, 0, false, fmt.Errorf("unknown s7 area %q in %q", string(addr[0]), addr)
	}
	rest := addr[1:]
	if rest == "" {
		return "", 0, 0, 0, false, fmt.Errorf("missing address in %q", addr)
	}
	if rest[0] >= '0' && rest[0] <= '9' {
		// 位简写 byte.bit
		isBit = true
		address, bitOffset, err = parseAddrTail(rest, true)
	} else {
		// 类型后缀 B/W/D/X
		switch strings.ToUpper(string(rest[0])) {
		case "X":
			isBit = true
		case "B", "W", "D":
		default:
			return "", 0, 0, 0, false, fmt.Errorf("unknown type suffix %q in %q", string(rest[0]), addr)
		}
		address, bitOffset, err = parseAddrTail(rest[1:], isBit)
	}
	if err != nil {
		return "", 0, 0, 0, false, err
	}
	return area, 0, address, bitOffset, isBit, nil
}

// parseAddrTail 解析 <addr>[.<bit>]。isBit 时要求 .bit。
func parseAddrTail(s string, isBit bool) (address, bitOffset int, err error) {
	parts := strings.SplitN(s, ".", 2)
	if address, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, fmt.Errorf("invalid address %q", parts[0])
	}
	if isBit {
		if len(parts) < 2 {
			return 0, 0, fmt.Errorf("bit address missing .bit in %q", s)
		}
		if bitOffset, err = strconv.Atoi(parts[1]); err != nil {
			return 0, 0, fmt.Errorf("invalid bit %q", parts[1])
		}
		if bitOffset < 0 || bitOffset > 7 {
			return 0, 0, fmt.Errorf("bit offset must be 0-7 in %q", s)
		}
	}
	return address, bitOffset, nil
}
