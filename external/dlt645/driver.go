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

// driver adapts iot_points.Driver to DLT645 TCP connection. addr is 12-digit BCD meter address.
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

// ReadPoints reads point by point: build read frame→send→parse response→decode by type/DI.
// Single-point failure marks Error and continues (avoid one bad point breaking entire table); all failure returns error.
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, 0, len(points))
	failCount := 0
	for i, p := range points {
		value, err := d.readPoint(p)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			failCount++
			// Timeout: the meter is silent, mark the rest failed instead of
			// waiting one more window per point.
			if iot_points.IsTimeoutErr(err) {
				for _, rest := range points[i+1:] {
					out = append(out, iot_points.Data{Name: rest.Name, Error: err.Error()})
					failCount++
				}
				break
			}
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

// readPoint reads and decodes single data ID.
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

// WritePoints writes point by point: encode Value to BCD→build write frame→send→verify normal response.
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

// transact sends request frame and reads one response frame, verifies response DI matches request, returns response data field.
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

// readFrame reads one complete response frame from connection (skips leading wakeup bytes like 0xFE).
func readFrame(r io.Reader) ([]byte, error) {
	one := make([]byte, 1)
	for { // Find frame start marker
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

// knownDI decode info for standard common data items: decimal places and signed (highest byte bit7 is sign bit).
// When Type is empty, decode per this table; unlisted DI treated as unsigned BCD integer.
var knownDI = map[[diLen]byte]struct {
	decimals int
	signed   bool
}{
	mustDI("00-01-00-00"): {2, false}, // Total forward active energy kWh
	mustDI("02-01-01-00"): {1, false}, // Phase A voltage V
	mustDI("02-02-01-00"): {3, true},  // Phase A current A
	mustDI("02-03-00-00"): {4, true},  // Instantaneous total active power kW
}

func mustDI(s string) [diLen]byte {
	di, err := ParseDI(s)
	if err != nil {
		panic(err)
	}
	return di
}

// decodeValue decodes response data field by point Type (or DI standard info if unspecified), values pass through ApplyScale engineering conversion.
// Integers without decimals/scaling return uint64/int64, values with decimals/scaling return float64.
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
		// Use BCD path below
	default:
		return nil, fmt.Errorf("unsupported type %q", p.Type)
	}
	signed := strings.EqualFold(strings.TrimSpace(p.Type), "BCD_SIGNED")
	decimals := 0
	if strings.TrimSpace(p.Type) == "" { // Empty Type uses known DI standard decimal places/sign
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

// decodeBCDValue decodes wire-order (low-byte-first) BCD data field to magnitude and sign. signed: highest byte bit7 is negative sign.
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

// decodeBinary decodes little-endian binary integer data field to float64 (for ApplyScale).
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
	if signed { // Sign-extend to signed integer
		shift := 64 - uint(n)*8
		return float64(int64(v<<shift) >> shift), nil
	}
	return float64(v), nil
}

// encodeWriteValue encodes point Value (numeric string) to write data field (BCD, low-byte-first).
// Byte count from Type (INT16/UINT16→2, INT32/UINT32→4, INT64/UINT64→8), unspecified uses natural length;
// Decimal places from known DI standard; negative values set highest byte sign bit.
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
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 { // Reverse byte order: little-endian
		out[i], out[j] = out[j], out[i]
	}
	if neg {
		out[len(out)-1] |= 0x80
	}
	return out, nil
}

// bcdBytes write byte count per Type, returns 0 if unspecified.
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

// bcdLen BCD encoding byte count for v (minimum 1).
func bcdLen(v uint64) int {
	n := 1
	for v >= 100 {
		v /= 100
		n++
	}
	return n
}
