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

package dlt645

import (
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
)

// driver 适配 iot_points.Driver 到 DLT645 TCP 连接。addr 为 12 位 BCD 表地址。
type driver struct {
	conn    net.Conn
	addr    string
	timeout time.Duration
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(conn net.Conn, addr string, timeout time.Duration) *driver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &driver{conn: conn, addr: addr, timeout: timeout}
}

// ReadPoints 逐点读取：构造读帧→发送→解析应答→按 type/DI 解码值。
// 单点失败标记 Error 并继续（避免一个坏点拖垮整张点位表）；全部失败才返回 error。
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, 0, len(points))
	failCount := 0
	for _, p := range points {
		value, err := d.readPoint(p)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			failCount++
			continue
		}
		out = append(out, iot_points.Data{
			Name:      p.Name,
			Value:     value,
			Timestamp: time.Now().UnixNano(),
		})
	}
	if len(points) > 0 && failCount == len(points) {
		return nil, fmt.Errorf("all %d dlt645 points failed: %s", failCount, out[0].Error)
	}
	return out, nil
}

// readPoint 读取并解码单个数据标识。
func (d *driver) readPoint(p iot_points.Point) (interface{}, error) {
	di, err := ParseDI(p.Addr)
	if err != nil {
		return nil, err
	}
	frame, err := BuildReadFrame(d.addr, di[:])
	if err != nil {
		return nil, err
	}
	raw, err := d.transact(frame, di)
	if err != nil {
		return nil, fmt.Errorf("dlt645: read %s (%s) failed: %v", p.Name, p.Addr, err)
	}
	return decodeValue(di, raw, p)
}

// WritePoints 逐点写入：Value BCD 编码→构造写帧→发送→校验正常应答。
func (d *driver) WritePoints(points []iot_points.Point) error {
	for _, p := range points {
		di, err := ParseDI(p.Addr)
		if err != nil {
			return err
		}
		data, err := encodeWriteValue(p)
		if err != nil {
			return fmt.Errorf("dlt645: encode write value %s (%s) failed: %v", p.Name, p.Addr, err)
		}
		frame, err := BuildWriteFrame(d.addr, di[:], data)
		if err != nil {
			return err
		}
		if _, err = d.transact(frame, di); err != nil {
			return fmt.Errorf("dlt645: write %s (%s) failed: %v", p.Name, p.Addr, err)
		}
	}
	return nil
}

// transact 发送请求帧并读取一帧应答，校验应答 DI 与请求一致，返回应答数据域。
func (d *driver) transact(frame []byte, di [diLen]byte) ([]byte, error) {
	_ = d.conn.SetDeadline(time.Now().Add(d.timeout))
	if _, err := d.conn.Write(frame); err != nil {
		return nil, err
	}
	resp, err := readFrame(d.conn)
	if err != nil {
		return nil, err
	}
	respDI, data, err := ParseResponse(resp)
	if err != nil {
		return nil, err
	}
	for i := 0; i < diLen; i++ {
		if respDI[i] != di[i] {
			return nil, fmt.Errorf("response DI %02X-%02X-%02X-%02X mismatch", respDI[3], respDI[2], respDI[1], respDI[0])
		}
	}
	return data, nil
}

// readFrame 从连接读取一帧完整应答帧（跳过前导唤醒字节如 0xFE）。
func readFrame(r io.Reader) ([]byte, error) {
	one := make([]byte, 1)
	for { // 找帧起始符
		if _, err := io.ReadFull(r, one); err != nil {
			return nil, err
		}
		if one[0] == frameStart {
			break
		}
	}
	head := make([]byte, 9) // addr(6) + 0x68 + ctrl + L
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[6] != frameStart {
		return nil, fmt.Errorf("dlt645: invalid address separator 0x%02X", head[6])
	}
	frame := make([]byte, minFrameLen+int(head[8]))
	frame[0] = frameStart
	copy(frame[1:10], head)
	if _, err := io.ReadFull(r, frame[10:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// knownDI 标准常见数据项的解码信息：小数位数与是否带符号（最高字节 bit7 为符号位）。
// Type 为空时按此表解码；未收录 DI 按无符号 BCD 整数处理。
var knownDI = map[[diLen]byte]struct {
	decimals int
	signed   bool
}{
	mustDI("00-01-00-00"): {2, false}, // 正向有功总电能 kWh
	mustDI("02-01-01-00"): {1, false}, // A 相电压 V
	mustDI("02-02-01-00"): {3, true},  // A 相电流 A
	mustDI("02-03-00-00"): {4, true},  // 瞬时总有功功率 kW
}

func mustDI(s string) [diLen]byte {
	di, err := ParseDI(s)
	if err != nil {
		panic(err)
	}
	return di
}

// decodeValue 按点位 Type（未指定则按 DI 标准信息）解码应答数据域，数值经 ApplyScale 工程量转换。
// 无小数无缩放的整数返回 uint64/int64，有小数或缩放返回 float64。
func decodeValue(di [diLen]byte, raw []byte, p iot_points.Point) (interface{}, error) {
	switch strings.ToUpper(strings.TrimSpace(p.Type)) {
	case iot_points.TypeBool:
		return len(raw) > 0 && raw[0] != 0, nil
	case iot_points.TypeString:
		return string(raw), nil
	case iot_points.TypeInt16, iot_points.TypeUint16, iot_points.TypeInt32,
		iot_points.TypeUint32, iot_points.TypeInt64, iot_points.TypeUint64:
		v, err := decodeBinary(raw, strings.ToUpper(strings.TrimSpace(p.Type)))
		if err != nil {
			return nil, err
		}
		return iot_points.ApplyScale(v, p), nil
	case "", "BCD", "BCD_SIGNED":
		// 走下方 BCD 路径
	default:
		return nil, fmt.Errorf("unsupported type %q", p.Type)
	}
	signed := strings.EqualFold(strings.TrimSpace(p.Type), "BCD_SIGNED")
	decimals := 0
	if strings.TrimSpace(p.Type) == "" { // Type 为空采用已知 DI 的标准小数位/符号
		if info, ok := knownDI[di]; ok {
			decimals, signed = info.decimals, info.signed
		}
	}
	mag, neg := decodeBCDValue(raw, signed)
	if decimals == 0 && p.Scale == 0 && p.Offset == 0 {
		switch {
		case neg:
			return -int64(mag), nil
		case signed:
			return int64(mag), nil
		default:
			return mag, nil
		}
	}
	v := float64(mag) / math.Pow10(decimals)
	if neg {
		v = -v
	}
	return iot_points.ApplyScale(v, p), nil
}

// decodeBCDValue 解码线序（低字节在前）BCD 数据域为原值与符号。signed 时最高字节 bit7 为负号。
func decodeBCDValue(raw []byte, signed bool) (mag uint64, neg bool) {
	rev := make([]byte, len(raw))
	for i, b := range raw {
		rev[len(raw)-1-i] = b
	}
	if signed && len(rev) > 0 && rev[0]&0x80 != 0 {
		neg = true
		rev[0] &= 0x7F
	}
	return DecodeBCD(rev), neg
}

// decodeBinary 解码小端二进制整数数据域为 float64（供 ApplyScale）。
func decodeBinary(raw []byte, typ string) (float64, error) {
	var n int
	var signed bool
	switch typ {
	case iot_points.TypeInt16, iot_points.TypeUint16:
		n, signed = 2, typ == iot_points.TypeInt16
	case iot_points.TypeInt32, iot_points.TypeUint32:
		n, signed = 4, typ == iot_points.TypeInt32
	case iot_points.TypeInt64, iot_points.TypeUint64:
		n, signed = 8, typ == iot_points.TypeInt64
	}
	if len(raw) < n {
		return 0, fmt.Errorf("data too short for %s: %d bytes", typ, len(raw))
	}
	var v uint64
	for i := n - 1; i >= 0; i-- {
		v = v<<8 | uint64(raw[i])
	}
	if signed { // 符号扩展为有符号整数
		shift := 64 - uint(n)*8
		return float64(int64(v<<shift) >> shift), nil
	}
	return float64(v), nil
}

// encodeWriteValue 把点位 Value（数值串）编码为写数据域（BCD，低字节在前）。
// 字节数取 Type（INT16/UINT16→2，INT32/UINT32→4，INT64/UINT64→8），未指定按自然位数；
// 小数位取已知 DI 标准值；负数最高字节点亮符号位。
func encodeWriteValue(p iot_points.Point) ([]byte, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(p.Value), 64)
	if err != nil {
		return nil, fmt.Errorf("invalid value %q", p.Value)
	}
	decimals := 0
	if di, derr := ParseDI(p.Addr); derr == nil {
		if info, ok := knownDI[di]; ok {
			decimals = info.decimals
		}
	}
	neg := f < 0
	v := uint64(math.Round(math.Abs(f) * math.Pow10(decimals)))
	n := bcdBytes(p.Type)
	if n == 0 {
		n = bcdLen(v)
	}
	out := EncodeBCD(v, n)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 { // 转线序：低字节在前
		out[i], out[j] = out[j], out[i]
	}
	if neg {
		out[len(out)-1] |= 0x80
	}
	return out, nil
}

// bcdBytes Type 对应的写入字节数，未指定返回 0。
func bcdBytes(typ string) int {
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case iot_points.TypeInt16, iot_points.TypeUint16:
		return 2
	case iot_points.TypeInt32, iot_points.TypeUint32:
		return 4
	case iot_points.TypeInt64, iot_points.TypeUint64:
		return 8
	}
	return 0
}

// bcdLen v 的 BCD 编码所需字节数（至少 1）。
func bcdLen(v uint64) int {
	n := 1
	for v >= 100 {
		v /= 100
		n++
	}
	return n
}
