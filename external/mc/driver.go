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

package mc

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/moge800/gomcprotocol"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
)

// bitDevices 位软元件，按位读写（MC 协议位单位批量访问）。
var bitDevices = map[string]bool{
	"X": true, "Y": true, "M": true, "L": true, "F": true, "V": true, "B": true, "S": true,
	"TC": true, "TS": true, "CC": true, "CS": true, "STC": true, "STS": true,
	"SB": true, "DX": true, "DY": true,
	"SM": true, // 特殊继电器是位软元件
}

// wordDevices 字软元件，按字读写（16 位/字）。
var wordDevices = map[string]bool{
	"D": true, "W": true, "R": true, "ZR": true, "Z": true,
	"TN": true, "STN": true, "CN": true, "SD": true, "SW": true,
}

// hexDevices 十六进制编址软元件，地址数字部分按十六进制解析（如 X1F=31）；其余按十进制。
var hexDevices = map[string]bool{
	"X": true, "Y": true, "B": true, "W": true, "ZR": true,
	"SB": true, "SW": true, "DX": true, "DY": true,
}

// driver 适配 iot_points.Driver 到 gomcprotocol 3E 客户端。
type driver struct {
	client *gomcprotocol.Client3E
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *gomcprotocol.Client3E) *driver {
	return &driver{client: client}
}

// ReadPoints 逐点读取。单点失败标记 Error；全部失败返回 error。
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, 0, len(points))
	failCount := 0
	for _, p := range points {
		dd, err := d.readPoint(p)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			failCount++
		} else {
			out = append(out, dd)
		}
	}
	if len(points) > 0 && failCount == len(points) {
		return nil, fmt.Errorf("all %d mc points failed", failCount)
	}
	return out, nil
}

// WritePoints 逐点写入。任一失败立即返回 error。
func (d *driver) WritePoints(points []iot_points.Point) error {
	for _, p := range points {
		if err := d.writePoint(p); err != nil {
			return err
		}
	}
	return nil
}

func (d *driver) readPoint(p iot_points.Point) (iot_points.Data, error) {
	device, offset, isBit, err := parseAddr(p.Addr)
	if err != nil {
		return iot_points.Data{}, err
	}
	if isBit {
		bits, err := d.client.ReadBits(device, offset, 1)
		if err != nil {
			return iot_points.Data{}, err
		}
		return iot_points.Data{Name: p.Name, Value: bits[0]}, nil
	}
	n, err := wordCount(p.Type)
	if err != nil {
		return iot_points.Data{}, err
	}
	words, err := d.client.ReadWords(device, offset, n)
	if err != nil {
		return iot_points.Data{}, err
	}
	val, err := decodeWords(words, p.Type)
	if err != nil {
		return iot_points.Data{}, err
	}
	// 数值类型做工程量转换（bool 不转换）
	if p.Scale != 0 || p.Offset != 0 {
		if f, ok := toFloat(val); ok {
			val = iot_points.ApplyScale(f, p)
		}
	}
	return iot_points.Data{Name: p.Name, Value: val}, nil
}

func (d *driver) writePoint(p iot_points.Point) error {
	device, offset, isBit, err := parseAddr(p.Addr)
	if err != nil {
		return err
	}
	if isBit {
		b, err := strconv.ParseBool(strings.TrimSpace(p.Value))
		if err != nil {
			return fmt.Errorf("parse bool value %q: %w", p.Value, err)
		}
		return d.client.WriteBits(device, offset, []bool{b})
	}
	words, err := encodeValue(p.Value, p.Type)
	if err != nil {
		return err
	}
	return d.client.WriteWords(device, offset, words)
}

// parseAddr 解析三菱软元件地址 <软元件><编号>，如 D100、M0、X1F、ZR10、TN5、STC3。
// 软元件前缀按最长匹配（STC/TN/ZR 等优先于 S/T/Z）；十六进制编址软元件的数字部分按十六进制解析。
func parseAddr(addr string) (device string, offset int, isBit bool, err error) {
	upper := strings.ToUpper(strings.TrimSpace(addr))
	if upper == "" {
		return "", 0, false, fmt.Errorf("empty mc addr")
	}
	for _, n := range []int{3, 2, 1} {
		if len(upper) > n && knownDevice(upper[:n]) {
			device = upper[:n]
			break
		}
	}
	if device == "" {
		return "", 0, false, fmt.Errorf("unknown mc device in %q", addr)
	}
	numStr := upper[len(device):]
	base := 10
	if hexDevices[device] {
		base = 16
	}
	n, perr := strconv.ParseUint(numStr, base, 32)
	if perr != nil {
		return "", 0, false, fmt.Errorf("invalid device number in %q", addr)
	}
	return device, int(n), bitDevices[device], nil
}

func knownDevice(d string) bool {
	return bitDevices[d] || wordDevices[d]
}

// wordCount 类型占用的字数（1 字 = 16 位）。空类型按 UINT16（1 字）。
func wordCount(typ string) (int, error) {
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case iot_points.TypeInt16, iot_points.TypeUint16, iot_points.TypeBool, "":
		return 1, nil
	case iot_points.TypeInt32, iot_points.TypeUint32, iot_points.TypeFloat32:
		return 2, nil
	case iot_points.TypeInt64, iot_points.TypeUint64, iot_points.TypeFloat64:
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported mc type %q", typ)
	}
}

// decodeWords 按 MELSEC 原生字节序（字内小端、低字在前）解码字序列为值。
func decodeWords(words []uint16, typ string) (interface{}, error) {
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case iot_points.TypeInt16, "":
		return int16(words[0]), nil
	case iot_points.TypeUint16:
		return words[0], nil
	case iot_points.TypeBool:
		return words[0] != 0, nil
	case iot_points.TypeInt32:
		return int32(join32(words)), nil
	case iot_points.TypeUint32:
		return join32(words), nil
	case iot_points.TypeFloat32:
		return math.Float32frombits(join32(words)), nil
	case iot_points.TypeInt64:
		return int64(join64(words)), nil
	case iot_points.TypeUint64:
		return join64(words), nil
	case iot_points.TypeFloat64:
		return math.Float64frombits(join64(words)), nil
	default:
		return nil, fmt.Errorf("unsupported mc type %q", typ)
	}
}

// encodeValue 解析写入值字符串为字序列（MELSEC 原生字节序）。空类型按 INT16。
func encodeValue(value, typ string) ([]uint16, error) {
	value = strings.TrimSpace(value)
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case iot_points.TypeInt16, "":
		v, err := strconv.ParseInt(value, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("parse int16 value %q: %w", value, err)
		}
		return []uint16{uint16(int16(v))}, nil
	case iot_points.TypeUint16:
		v, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("parse uint16 value %q: %w", value, err)
		}
		return []uint16{uint16(v)}, nil
	case iot_points.TypeInt32:
		v, err := strconv.ParseInt(value, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("parse int32 value %q: %w", value, err)
		}
		return split32(uint32(int32(v))), nil
	case iot_points.TypeUint32:
		v, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("parse uint32 value %q: %w", value, err)
		}
		return split32(uint32(v)), nil
	case iot_points.TypeFloat32:
		f, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return nil, fmt.Errorf("parse float32 value %q: %w", value, err)
		}
		return split32(math.Float32bits(float32(f))), nil
	case iot_points.TypeInt64:
		v, err := strconv.ParseInt(value, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("parse int64 value %q: %w", value, err)
		}
		return split64(uint64(v)), nil
	case iot_points.TypeUint64:
		v, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("parse uint64 value %q: %w", value, err)
		}
		return split64(v), nil
	case iot_points.TypeFloat64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("parse float64 value %q: %w", value, err)
		}
		return split64(math.Float64bits(f)), nil
	default:
		return nil, fmt.Errorf("unsupported mc type %q", typ)
	}
}

// join32 组装 2 字为 32 位值（低字在前）。
func join32(w []uint16) uint32 {
	return uint32(w[1])<<16 | uint32(w[0])
}

// join64 组装 4 字为 64 位值（低字在前）。
func join64(w []uint16) uint64 {
	return uint64(join32(w[2:]))<<32 | uint64(join32(w[:2]))
}

// split32 拆分 32 位值为 2 字（低字在前）。
func split32(v uint32) []uint16 {
	return []uint16{uint16(v), uint16(v >> 16)}
}

// split64 拆分 64 位值为 4 字（低字在前）。
func split64(v uint64) []uint16 {
	return []uint16{uint16(v), uint16(v >> 16), uint16(v >> 32), uint16(v >> 48)}
}

// toFloat 数值转 float64（bool 等非数值返回 ok=false）。
func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int16:
		return float64(n), true
	case uint16:
		return float64(n), true
	case int32:
		return float64(n), true
	case uint32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}
