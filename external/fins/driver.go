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

// readPlan is a parsed and validated point ready for wire encoding.
type readPlan struct {
	point  iot_points.Point
	idx    int // position in the original point list
	typ    string
	area   byte
	addr   uint16
	bit    byte
	isBit  bool
	strLen int // STRING byte length (>0 only for STRING points)
	nItems int // 0x0104 items needed: 1 for bit, word count otherwise
}

// ReadPoints batch reads points via one or more 0x0104 multiple memory area read commands
// (max 167 items per frame per W342). Batch failure falls back to per-point 0x0101 reads.
// Single-point failure marks Error; all failure returns error.
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, len(points))
	plans := make([]*readPlan, len(points))
	failCount := 0
	for i, p := range points {
		pl, err := newReadPlan(p)
		if err != nil {
			out[i] = iot_points.Data{Name: p.Name, Error: err.Error()}
			failCount++
			continue
		}
		pl.idx = i
		plans[i] = pl
	}

	// Greedy batching: fill each 0x0104 frame up to the item limit, preserving point order.
	var batch []*readPlan
	items := 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		d.readBatch(batch, out, &failCount)
		batch, items = nil, 0
	}
	for _, pl := range plans {
		if pl == nil {
			continue
		}
		if pl.nItems > finsclient.MaxMultipleReadItems {
			d.readSingle(pl, out, &failCount)
			continue
		}
		if items+pl.nItems > finsclient.MaxMultipleReadItems {
			flush()
		}
		batch = append(batch, pl)
		items += pl.nItems
	}
	flush()

	if len(points) > 0 && failCount == len(points) {
		return nil, fmt.Errorf("all %d fins points failed", failCount)
	}
	return out, nil
}

// readBatch reads one batch of plans with a single 0x0104 command; on error falls back to per-point reads.
func (d *driver) readBatch(batch []*readPlan, out []iot_points.Data, failCount *int) {
	items := make([]finsclient.MultipleItem, 0, len(batch)*2)
	for _, pl := range batch {
		for k := 0; k < pl.nItems; k++ {
			item := finsclient.MultipleItem{Area: pl.area, Address: pl.addr + uint16(k)}
			if pl.isBit {
				item.Bit = pl.bit
			}
			items = append(items, item)
		}
	}
	data, err := d.client.ReadMultiple(items)
	if err != nil {
		// Only fall back on PLC rejection (EndCodeError, fast response): the PLC answered but
		// does not support 0x0104, so retry point by point via 0x0101. Transport/timeout errors
		// are connection-level: mark all points failed (triggers node-level reconnect) instead of
		// amplifying the timeout N-fold with per-point reads.
		if _, ok := err.(finsclient.EndCodeError); ok {
			for _, pl := range batch {
				d.readSingle(pl, out, failCount)
			}
			return
		}
		for _, pl := range batch {
			out[pl.idx] = iot_points.Data{Name: pl.point.Name, Error: err.Error()}
			*failCount++
		}
		return
	}
	off := 0
	for _, pl := range batch {
		val, err := decodePlanItems(pl, data[off:off+pl.nItems])
		off += pl.nItems
		if err != nil {
			out[pl.idx] = iot_points.Data{Name: pl.point.Name, Error: err.Error()}
			*failCount++
			continue
		}
		out[pl.idx] = iot_points.Data{Name: pl.point.Name, Value: val}
	}
}

// readSingle reads one plan via the legacy per-point path (also used as 0x0104 fallback).
func (d *driver) readSingle(pl *readPlan, out []iot_points.Data, failCount *int) {
	dd, err := d.readPoint(pl.point)
	if err != nil {
		out[pl.idx] = iot_points.Data{Name: pl.point.Name, Error: err.Error()}
		*failCount++
		return
	}
	out[pl.idx] = dd
}

// newReadPlan parses and validates a point for reading.
func newReadPlan(p iot_points.Point) (*readPlan, error) {
	area, address, bitOffset, isBit, strLen, err := parseAddr(p.Addr)
	if err != nil {
		return nil, err
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	if isBit {
		if typ == iot_points.TypeString {
			return nil, fmt.Errorf("STRING requires a word address like %s:20", p.Addr)
		}
		return &readPlan{point: p, typ: typ, area: area, addr: address, bit: bitOffset, isBit: true, nItems: 1}, nil
	}
	if strLen > 0 {
		if typ != iot_points.TypeString {
			return nil, fmt.Errorf("address %s carries string length; set type STRING", p.Addr)
		}
		return &readPlan{point: p, typ: typ, area: area, addr: address, strLen: strLen, nItems: (strLen + 1) / 2}, nil
	}
	if typ == iot_points.TypeString {
		return nil, fmt.Errorf("STRING requires a byte length suffix, e.g. %s:20", p.Addr)
	}
	if typ == iot_points.TypeBool {
		return nil, fmt.Errorf("BOOL requires a bit address like %s.0", p.Addr)
	}
	count, err := wordCount(typ)
	if err != nil {
		return nil, err
	}
	return &readPlan{point: p, typ: typ, area: area, addr: address, nItems: count}, nil
}

// decodePlanItems decodes one plan's value from its 0x0104 item data (2 bytes per word item, 1 byte per bit item).
func decodePlanItems(pl *readPlan, itemData [][]byte) (interface{}, error) {
	if pl.isBit {
		if len(itemData) == 0 || len(itemData[0]) == 0 {
			return nil, fmt.Errorf("empty bit data")
		}
		return itemData[0][0]&0x01 != 0, nil
	}
	raw := make([]byte, 0, len(itemData)*2)
	for _, d := range itemData {
		raw = append(raw, d...)
	}
	if pl.strLen > 0 {
		if len(raw) < pl.strLen {
			return nil, fmt.Errorf("short string data %d < %d", len(raw), pl.strLen)
		}
		return decodeString(raw[:pl.strLen]), nil
	}
	if len(raw) < pl.nItems*2 {
		return nil, fmt.Errorf("short data %d bytes for %d words", len(raw), pl.nItems)
	}
	words := bytesToWords(raw[:pl.nItems*2])
	if pl.nItems >= 2 && pl.point.Endian != "" {
		words = applyEndian(words, pl.point.Endian)
	}
	val, rawF := decodeWords(pl.typ, words)
	if pl.point.Scale != 0 || pl.point.Offset != 0 {
		val = iot_points.ApplyScale(rawF, pl.point)
	}
	return val, nil
}

// readPoint reads a single point (0x0101 path): bit area for .bit, STRING for length suffix,
// otherwise word area decoded by Type with Scale/Offset engineering conversion.
func (d *driver) readPoint(p iot_points.Point) (iot_points.Data, error) {
	area, address, bitOffset, isBit, strLen, err := parseAddr(p.Addr)
	if err != nil {
		return iot_points.Data{}, err
	}
	if isBit {
		if strings.ToUpper(strings.TrimSpace(p.Type)) == iot_points.TypeString {
			return iot_points.Data{}, fmt.Errorf("STRING requires a word address like %s:20", p.Addr)
		}
		b, err := d.client.ReadBits(area, address, bitOffset, 1)
		if err != nil {
			return iot_points.Data{}, err
		}
		return iot_points.Data{Name: p.Name, Value: b[0]}, nil
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	if strLen > 0 {
		if typ != iot_points.TypeString {
			return iot_points.Data{}, fmt.Errorf("address %s carries string length; set type STRING", p.Addr)
		}
		w, err := d.client.ReadWords(area, address, uint16((strLen+1)/2))
		if err != nil {
			return iot_points.Data{}, err
		}
		raw := wordsToBytes(w)
		return iot_points.Data{Name: p.Name, Value: decodeString(raw[:strLen])}, nil
	}
	if typ == iot_points.TypeString {
		return iot_points.Data{}, fmt.Errorf("STRING requires a byte length suffix, e.g. %s:20", p.Addr)
	}
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
	if count >= 2 && p.Endian != "" {
		w = applyEndian(w, p.Endian)
	}
	val, raw := decodeWords(typ, w)
	if p.Scale != 0 || p.Offset != 0 {
		val = iot_points.ApplyScale(raw, p)
	}
	return iot_points.Data{Name: p.Name, Value: val}, nil
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

// writePoint writes a single point. With .bit writes bit area; with STRING writes byte length suffix address;
// otherwise encodes by Type into word sequence.
func (d *driver) writePoint(p iot_points.Point) error {
	area, address, bitOffset, isBit, strLen, err := parseAddr(p.Addr)
	if err != nil {
		return err
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	if isBit {
		if typ == iot_points.TypeString {
			return fmt.Errorf("STRING requires a word address like %s:20", p.Addr)
		}
		b, err := parseBoolValue(p.Value)
		if err != nil {
			return fmt.Errorf("parse bool value %q: %w", p.Value, err)
		}
		return d.client.WriteBits(area, address, bitOffset, []bool{b})
	}
	if strLen > 0 {
		if typ != iot_points.TypeString {
			return fmt.Errorf("address %s carries string length; set type STRING", p.Addr)
		}
		return d.client.WriteWords(area, address, encodeStringWords(p.Value, strLen))
	}
	if typ == iot_points.TypeString {
		return fmt.Errorf("STRING requires a byte length suffix, e.g. %s:20", p.Addr)
	}
	words, err := encodeWords(typ, p.Value)
	if err != nil {
		return err
	}
	if len(words) >= 2 && p.Endian != "" {
		words = applyEndian(words, p.Endian)
	}
	return d.client.WriteWords(area, address, words)
}

// parseAddr parses Omron memory area address forms:
//
//	<area><number>          word area
//	<area><number>.<bit>    bit area (bit 0-15)
//	<area><number>:<strlen> word area + STRING byte length
//
// Areas: CIO I/O area, D/DM data area, W/WR work area, H/HR holding area, A/AR auxiliary area.
// Uses W342 (CS/CJ series) standard values.
func parseAddr(addr string) (area byte, address uint16, bitOffset byte, isBit bool, strLen int, err error) {
	s := strings.TrimSpace(addr)
	if s == "" {
		return 0, 0, 0, false, 0, fmt.Errorf("empty fins addr")
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
		return 0, 0, 0, false, 0, fmt.Errorf("unknown fins area in %q (expect D/DM/W/WR/H/HR/A/AR/CIO)", addr)
	}
	if dotIdx := strings.IndexByte(rest, '.'); dotIdx >= 0 {
		n, perr := strconv.ParseUint(strings.TrimSpace(rest[:dotIdx]), 10, 32)
		if perr != nil || n > 0xffff {
			return 0, 0, 0, false, 0, fmt.Errorf("invalid fins address %q", addr)
		}
		b, perr := strconv.ParseUint(strings.TrimSpace(rest[dotIdx+1:]), 10, 32)
		if perr != nil || b > 15 {
			return 0, 0, 0, false, 0, fmt.Errorf("invalid fins bit offset in %q", addr)
		}
		return bitArea, uint16(n), byte(b), true, 0, nil
	}
	if colonIdx := strings.IndexByte(rest, ':'); colonIdx >= 0 {
		n, perr := strconv.ParseUint(strings.TrimSpace(rest[:colonIdx]), 10, 32)
		if perr != nil || n > 0xffff {
			return 0, 0, 0, false, 0, fmt.Errorf("invalid fins address %q", addr)
		}
		l, perr := strconv.ParseUint(strings.TrimSpace(rest[colonIdx+1:]), 10, 32)
		if perr != nil || l == 0 || l > 0xffff {
			return 0, 0, 0, false, 0, fmt.Errorf("invalid fins string length in %q", addr)
		}
		return wordArea, uint16(n), 0, false, int(l), nil
	}
	n, perr := strconv.ParseUint(strings.TrimSpace(rest), 10, 32)
	if perr != nil || n > 0xffff {
		return 0, 0, 0, false, 0, fmt.Errorf("invalid fins address %q", addr)
	}
	return wordArea, uint16(n), 0, false, 0, nil
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

// encodeStringWords encodes string into big-endian words for strLen bytes: truncate long values, zero-pad to word boundary.
func encodeStringWords(value string, strLen int) []uint16 {
	b := []byte(value)
	if len(b) > strLen {
		b = b[:strLen]
	}
	padded := make([]byte, (strLen+1)/2*2)
	copy(padded, b)
	return bytesToWords(padded)
}

// decodeString converts raw bytes to string, cutting at the first NUL terminator.
func decodeString(b []byte) string {
	s := string(b)
	if idx := strings.IndexByte(s, 0); idx >= 0 {
		s = s[:idx]
	}
	return s
}

// applyEndian reorders word sequence by point byte order (device original order ABCD big-endian high-word-first).
// CDAB=word swap, BADC=word-inner byte swap, DCBA=both; four transforms are involutions, same function for encode/decode.
func applyEndian(words []uint16, endian string) []uint16 {
	e := strings.ToUpper(strings.TrimSpace(endian))
	if e == "" || e == "ABCD" {
		return words
	}
	out := make([]uint16, len(words))
	byteSwap := e == "BADC" || e == "DCBA"
	wordSwap := e == "CDAB" || e == "DCBA"
	for i, w := range words {
		j := i
		if wordSwap {
			j = len(words) - 1 - i
		}
		if byteSwap {
			w = w>>8 | w<<8
		}
		out[j] = w
	}
	return out
}

// wordsToBytes flattens big-endian words to bytes.
func wordsToBytes(w []uint16) []byte {
	b := make([]byte, len(w)*2)
	for i, v := range w {
		b[i*2] = byte(v >> 8)
		b[i*2+1] = byte(v)
	}
	return b
}

// bytesToWords groups even-length bytes into big-endian words.
func bytesToWords(b []byte) []uint16 {
	w := make([]uint16, len(b)/2)
	for i := range w {
		w[i] = uint16(b[i*2])<<8 | uint16(b[i*2+1])
	}
	return w
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
