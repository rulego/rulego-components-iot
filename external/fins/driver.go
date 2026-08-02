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

package fins

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	finsclient "github.com/rulego/rulego-components-iot/pkg/fins_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
)

// driver adapts iot_points.Driver to Omron FINS client.
type driver struct {
	client *finsclient.Client
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *finsclient.Client) *driver {
	return &driver{client: client}
}

// ReadPoints reads point by point. Single-point failure marks Error; all failure returns error.
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
		return nil, fmt.Errorf("all %d fins points failed", failCount)
	}
	return out, nil
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

// readPoint reads a single point. With .bit reads bit area; otherwise reads word area and decodes by Type, Scale/Offset for engineering conversion.
func (d *driver) readPoint(p iot_points.Point) (iot_points.Data, error) {
	area, address, bitOffset, isBit, err := parseAddr(p.Addr)
	if err != nil {
		return iot_points.Data{}, err
	}
	if isBit {
		b, err := d.client.ReadBits(area, address, bitOffset, 1)
		if err != nil {
			return iot_points.Data{}, err
		}
		return iot_points.Data{Name: p.Name, Value: b[0]}, nil
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	if typ == iot_points.TypeBool {
		return iot_points.Data{}, fmt.Errorf("BOOL requires a bit address like %s.0", p.Addr)
	}
	count, err := wordCount(typ)
	if err != nil {
		return iot_points.Data{}, err
	}
	w, err := d.client.ReadWords(area, address, uint16(count))
	if err != nil {
		return iot_points.Data{}, err
	}
	val, raw := decodeWords(typ, w)
	if p.Scale != 0 || p.Offset != 0 {
		val = iot_points.ApplyScale(raw, p)
	}
	return iot_points.Data{Name: p.Name, Value: val}, nil
}

// writePoint writes a single point. With .bit writes bit area; otherwise encodes by Type into word sequence.
func (d *driver) writePoint(p iot_points.Point) error {
	area, address, bitOffset, isBit, err := parseAddr(p.Addr)
	if err != nil {
		return err
	}
	if isBit {
		b, err := parseBoolValue(p.Value)
		if err != nil {
			return fmt.Errorf("parse bool value %q: %w", p.Value, err)
		}
		return d.client.WriteBits(area, address, bitOffset, []bool{b})
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	words, err := encodeWords(typ, p.Value)
	if err != nil {
		return err
	}
	return d.client.WriteWords(area, address, words)
}

// parseAddr parses Omron memory area address: <area><number>[.<bit>].
// Areas: CIO I/O area, D/DM data area, W/WR work area, H/HR holding area, A/AR auxiliary area.
// With .bit returns bit area code, otherwise word area code. Uses W342 (CS/CJ series) standard values.
func parseAddr(addr string) (area byte, address uint16, bitOffset byte, isBit bool, err error) {
	s := strings.TrimSpace(addr)
	if s == "" {
		return 0, 0, 0, false, fmt.Errorf("empty fins addr")
	}
	upper := strings.ToUpper(s)
	var wordArea, bitArea byte
	var rest string
	switch {
	case strings.HasPrefix(upper, "CIO"):
		wordArea, bitArea, rest = finsclient.MemoryAreaCIOWord, finsclient.MemoryAreaCIOBit, s[3:]
	case strings.HasPrefix(upper, "DM"):
		wordArea, bitArea, rest = finsclient.MemoryAreaDMWord, finsclient.MemoryAreaDMBit, s[2:]
	case strings.HasPrefix(upper, "WR"):
		wordArea, bitArea, rest = finsclient.MemoryAreaWRWord, finsclient.MemoryAreaWRBit, s[2:]
	case strings.HasPrefix(upper, "HR"):
		wordArea, bitArea, rest = finsclient.MemoryAreaHRWord, finsclient.MemoryAreaHRBit, s[2:]
	case strings.HasPrefix(upper, "AR"):
		wordArea, bitArea, rest = finsclient.MemoryAreaARWord, finsclient.MemoryAreaARBit, s[2:]
	case strings.HasPrefix(upper, "D"):
		wordArea, bitArea, rest = finsclient.MemoryAreaDMWord, finsclient.MemoryAreaDMBit, s[1:]
	case strings.HasPrefix(upper, "W"):
		wordArea, bitArea, rest = finsclient.MemoryAreaWRWord, finsclient.MemoryAreaWRBit, s[1:]
	case strings.HasPrefix(upper, "H"):
		wordArea, bitArea, rest = finsclient.MemoryAreaHRWord, finsclient.MemoryAreaHRBit, s[1:]
	case strings.HasPrefix(upper, "A"):
		wordArea, bitArea, rest = finsclient.MemoryAreaARWord, finsclient.MemoryAreaARBit, s[1:]
	default:
		return 0, 0, 0, false, fmt.Errorf("unknown fins area in %q (expect D/DM/W/WR/H/HR/A/AR/CIO)", addr)
	}
	parts := strings.SplitN(rest, ".", 2)
	n, perr := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if perr != nil || n > 0xffff {
		return 0, 0, 0, false, fmt.Errorf("invalid fins address %q", addr)
	}
	address = uint16(n)
	if len(parts) == 2 {
		b, perr := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if perr != nil || b > 15 {
			return 0, 0, 0, false, fmt.Errorf("invalid fins bit offset in %q", addr)
		}
		bitOffset = byte(b)
		isBit = true
	}
	if isBit {
		area = bitArea
	} else {
		area = wordArea
	}
	return area, address, bitOffset, isBit, nil
}

// wordCount maps type to word count (16bit); unknown type errors.
func wordCount(typ string) (int, error) {
	switch typ {
	case iot_points.TypeInt16, iot_points.TypeUint16, "":
		return 1, nil
	case iot_points.TypeInt32, iot_points.TypeUint32, iot_points.TypeFloat32:
		return 2, nil
	case iot_points.TypeInt64, iot_points.TypeUint64, iot_points.TypeFloat64:
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported fins type %q", typ)
	}
}

// decodeWords converts word sequence (big-endian) to typed value, also returns raw float for Scale conversion.
func decodeWords(typ string, w []uint16) (val interface{}, raw float64) {
	switch typ {
	case iot_points.TypeInt16:
		v := int16(w[0])
		return v, float64(v)
	case iot_points.TypeUint16, "":
		return w[0], float64(w[0])
	case iot_points.TypeInt32:
		v := int32(wordsToUint32(w))
		return v, float64(v)
	case iot_points.TypeUint32:
		v := wordsToUint32(w)
		return v, float64(v)
	case iot_points.TypeInt64:
		v := int64(wordsToUint64(w))
		return v, float64(v)
	case iot_points.TypeUint64:
		v := wordsToUint64(w)
		return v, float64(v)
	case iot_points.TypeFloat32:
		v := math.Float32frombits(wordsToUint32(w))
		return v, float64(v)
	case iot_points.TypeFloat64:
		v := math.Float64frombits(wordsToUint64(w))
		return v, v
	default:
		return nil, 0
	}
}

// encodeWords encodes string value to big-endian word sequence by type. Signed types use ParseInt for negative values.
func encodeWords(typ, value string) ([]uint16, error) {
	switch typ {
	case iot_points.TypeInt16:
		v, err := strconv.ParseInt(value, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("parse int16 value %q: %w", value, err)
		}
		return []uint16{uint16(int16(v))}, nil
	case iot_points.TypeUint16, "":
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
		return uint32ToWords(uint32(int32(v))), nil
	case iot_points.TypeUint32:
		v, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("parse uint32 value %q: %w", value, err)
		}
		return uint32ToWords(uint32(v)), nil
	case iot_points.TypeInt64:
		v, err := strconv.ParseInt(value, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("parse int64 value %q: %w", value, err)
		}
		return uint64ToWords(uint64(v)), nil
	case iot_points.TypeUint64:
		v, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("parse uint64 value %q: %w", value, err)
		}
		return uint64ToWords(v), nil
	case iot_points.TypeFloat32:
		f, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return nil, fmt.Errorf("parse float32 value %q: %w", value, err)
		}
		return uint32ToWords(math.Float32bits(float32(f))), nil
	case iot_points.TypeFloat64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("parse float64 value %q: %w", value, err)
		}
		return uint64ToWords(math.Float64bits(f)), nil
	default:
		return nil, fmt.Errorf("unsupported fins type %q", typ)
	}
}

// wordsToUint32 big-endian double word -> uint32.
func wordsToUint32(w []uint16) uint32 {
	return uint32(w[0])<<16 | uint32(w[1])
}

// uint32ToWords uint32 -> big-endian double word.
func uint32ToWords(v uint32) []uint16 {
	return []uint16{uint16(v >> 16), uint16(v)}
}

// wordsToUint64 big-endian four words -> uint64.
func wordsToUint64(w []uint16) uint64 {
	return uint64(w[0])<<48 | uint64(w[1])<<32 | uint64(w[2])<<16 | uint64(w[3])
}

// uint64ToWords uint64 -> big-endian four words.
func uint64ToWords(v uint64) []uint16 {
	return []uint16{uint16(v >> 48), uint16(v >> 32), uint16(v >> 16), uint16(v)}
}

// parseBoolValue string -> bool, supports 0/1/true/false.
func parseBoolValue(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("invalid boolean value")
	}
}
