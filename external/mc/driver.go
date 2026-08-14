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

// bitDevices bit devices, read/write by bit (MC protocol bit unit batch access).
var bitDevices = map[string]bool{
	"X": true, "Y": true, "M": true, "L": true, "F": true, "V": true, "B": true, "S": true,
	"TC": true, "TS": true, "CC": true, "CS": true, "STC": true, "STS": true,
	"SB": true, "DX": true, "DY": true,
	"SM": true, // Special relay is a bit device
}

// wordDevices word devices, read/write by word (16-bit/word).
var wordDevices = map[string]bool{
	"D": true, "W": true, "R": true, "ZR": true, "Z": true,
	"TN": true, "STN": true, "CN": true, "SD": true, "SW": true,
}

// hexDevices hex-addressed devices, address numeric part parsed as hex (e.g. X1F=31); others use decimal.
var hexDevices = map[string]bool{
	"X": true, "Y": true, "B": true, "W": true, "ZR": true,
	"SB": true, "SW": true, "DX": true, "DY": true,
}

// driver adapts iot_points.Driver to gomcprotocol 3E client.
type driver struct {
	client *gomcprotocol.Client3E
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *gomcprotocol.Client3E) *driver {
	return &driver{client: client}
}

// ReadPoints reads point by point. Single-point failure marks Error; all failure returns error.
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out, failCount := readEachPoint(points, d.readPoint)
	if len(points) > 0 && failCount == len(points) {
		return nil, fmt.Errorf("all %d mc points failed", failCount)
	}
	return out, nil
}

// readEachPoint reads via read one point at a time; a timeout marks the
// remaining points failed instead of waiting one more window per point.
// Separated so the short-circuit is testable without a PLC.
func readEachPoint(points []iot_points.Point, read func(iot_points.Point) (iot_points.Data, error)) ([]iot_points.Data, int) {
	out := make([]iot_points.Data, 0, len(points))
	failCount := 0
	for i, p := range points {
		dd, err := read(p)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			failCount++
			// Timeout: the PLC is silent, mark the rest failed instead of
			// waiting one more window per point.
			if iot_points.IsTimeoutErr(err) {
				for _, rest := range points[i+1:] {
					out = append(out, iot_points.Data{Name: rest.Name, Error: err.Error()})
					failCount++
				}
				break
			}
		} else {
			out = append(out, dd)
		}
	}
	return out, failCount
}

// WritePoints writes point by point. Any failure returns error immediately.
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
	// Numeric types do engineering conversion (bool not converted)
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

// parseAddr parses Mitsubishi device address <device><number>, e.g. D100, M0, X1F, ZR10, TN5, STC3.
// Device prefix matches longest first (STC/TN/ZR take precedence over S/T/Z); hex-addressed devices parse numeric part as hex.
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

// wordCount word count per type (1 word = 16 bits). Empty type defaults to UINT16 (1 word).
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

// decodeWords decodes word sequence to value per MELSEC native byte order (little-endian within word, low word first).
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

// encodeValue parses write value string to word sequence (MELSEC native byte order). Empty type defaults to INT16.
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

// join32 assembles 2 words into 32-bit value (low word first).
func join32(w []uint16) uint32 {
	return uint32(w[1])<<16 | uint32(w[0])
}

// join64 assembles 4 words into 64-bit value (low word first).
func join64(w []uint16) uint64 {
	return uint64(join32(w[2:]))<<32 | uint64(join32(w[:2]))
}

// split32 splits 32-bit value into 2 words (low word first).
func split32(v uint32) []uint16 {
	return []uint16{uint16(v), uint16(v >> 16)}
}

// split64 splits 64-bit value into 4 words (low word first).
func split64(v uint64) []uint16 {
	return []uint16{uint16(v), uint16(v >> 16), uint16(v >> 32), uint16(v >> 48)}
}

// toFloat converts numeric to float64 (bool etc. return ok=false).
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
