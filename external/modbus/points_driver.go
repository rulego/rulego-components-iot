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

package modbus

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/simonvetter/modbus"
)

// Modicon address types (distinguished by first digit).
const (
	modiconCoil = "coil"             // 0xxxx coil (read-write)
	modiconDI   = "discrete_input"   // 1xxxx discrete input (read-only)
	modiconIR   = "input_register"   // 3xxxx input register (read-only)
	modiconHR   = "holding_register" // 4xxxx holding register (read-write)
)

// driver adapts iot_points.Driver to RetryableModbusClient. Stateless, holds client reference.
type driver struct {
	client *RetryableModbusClient
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *RetryableModbusClient) *driver {
	return &driver{client: client}
}

// Batch read limits (Modbus protocol) and address merge tolerance.
const (
	modbusMaxRegsPerRead = 125  // registers per request
	modbusMaxBitsPerRead = 2000 // coils/discrete inputs per request
	modbusMergeGap       = 8    // hole allowed between neighbors, still merged into one block
)

// readPlan is a point's placement inside a batch block.
type readPlan struct {
	point   iot_points.Point
	index   int    // index in input points, keeps output order
	addr    uint16 // protocol address (0-based)
	width   uint16 // registers occupied (bits for coil/discrete input)
	typ     string // normalized type
	kind    string
	regType modbus.RegType
}

// ReadPoints reads by Point.Addr(Modicon) + Type, merging neighboring addresses into batch requests.
// Single failure marks Error; all failures return error.
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, len(points))
	groups, keys := d.planGroups(points, out)
	for _, k := range keys {
		g := groups[k]
		sort.SliceStable(g, func(i, j int) bool { return g[i].addr < g[j].addr })
		for _, blk := range chunkPlans(g) {
			d.readBlock(blk, out)
		}
	}
	failCount := 0
	for i := range out {
		if out[i].Error != "" {
			failCount++
		}
	}
	if len(points) > 0 && failCount == len(points) {
		return nil, fmt.Errorf("all %d modbus points failed", failCount)
	}
	return out, nil
}

// planGroups groups points by (regType, kind); only same-group points may merge.
// Points with bad address or unsupported type are read individually into out. Returns groups and stable key order.
func (d *driver) planGroups(points []iot_points.Point, out []iot_points.Data) (map[string][]readPlan, []string) {
	groups := make(map[string][]readPlan)
	var keys []string
	for i, p := range points {
		regType, addr, kind, err := parseModiconAddr(p.Addr)
		if err != nil {
			out[i] = d.readOne(p)
			continue
		}
		typ := strings.ToUpper(strings.TrimSpace(p.Type))
		width, ok := pointRegWidth(typ, kind)
		if !ok {
			out[i] = d.readOne(p)
			continue
		}
		key := fmt.Sprintf("%d/%s", regType, kind)
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], readPlan{
			point: p, index: i, addr: addr, width: width, typ: typ, kind: kind, regType: regType,
		})
	}
	return groups, keys
}

// pointRegWidth returns registers occupied by a point (1 bit for coil/discrete input area);
// ok=false when the type is unsupported and cannot be planned.
func pointRegWidth(typ, kind string) (uint16, bool) {
	if kind == modiconCoil || kind == modiconDI {
		return 1, true
	}
	switch typ {
	case iot_points.TypeBool, iot_points.TypeUint16, iot_points.TypeInt16, "":
		return 1, true
	case iot_points.TypeUint32, iot_points.TypeInt32, iot_points.TypeFloat32:
		return 2, true
	case iot_points.TypeUint64, iot_points.TypeInt64, iot_points.TypeFloat64:
		return 4, true
	}
	return 0, false
}

// chunkPlans splits an address-sorted group into blocks: neighbors within modbusMergeGap merge,
// capped by per-request limit and the 0xffff end address.
func chunkPlans(g []readPlan) [][]readPlan {
	if len(g) == 0 {
		return nil
	}
	limit := uint32(modbusMaxRegsPerRead)
	if g[0].kind == modiconCoil || g[0].kind == modiconDI {
		limit = modbusMaxBitsPerRead
	}
	var blocks [][]readPlan
	cur := []readPlan{g[0]}
	start := uint32(g[0].addr)
	end := start + uint32(g[0].width) // exclusive
	for _, p := range g[1:] {
		a := uint32(p.addr)
		newEnd := end
		if a+uint32(p.width) > newEnd {
			newEnd = a + uint32(p.width)
		}
		if a > end+modbusMergeGap || newEnd-start > limit || newEnd > 0x10000 {
			blocks = append(blocks, cur)
			cur = []readPlan{p}
			start = a
			end = a + uint32(p.width)
			continue
		}
		cur = append(cur, p)
		end = newEnd
	}
	return append(blocks, cur)
}

// readBlock reads one block in a single request and slices the result per point.
// On block failure falls back to per-point reads, so one unreadable address does not lose the whole block.
func (d *driver) readBlock(blk []readPlan, out []iot_points.Data) {
	if len(blk) == 1 {
		out[blk[0].index] = d.readOne(blk[0].point)
		return
	}
	start := uint32(blk[0].addr)
	var end uint32
	for _, p := range blk {
		if e := uint32(p.addr) + uint32(p.width); e > end {
			end = e
		}
	}
	quantity := uint16(end - start)
	if blk[0].kind == modiconCoil || blk[0].kind == modiconDI {
		bits, err := d.readBits(blk[0].addr, quantity, blk[0].kind)
		if err != nil || len(bits) < int(quantity) {
			d.fallbackBlock(blk, out)
			return
		}
		for _, p := range blk {
			out[p.index] = bitToData(bits[uint32(p.addr)-start], p.point, p.typ)
		}
		return
	}
	words, err := d.client.ReadRegisters(blk[0].addr, quantity, blk[0].regType)
	if err != nil || len(words) < int(quantity) {
		d.fallbackBlock(blk, out)
		return
	}
	lowWordFirst := d.client.lowWordFirst()
	for _, p := range blk {
		off := uint32(p.addr) - start
		out[p.index] = wordsToData(words[off:off+uint32(p.width)], p.point, p.typ, lowWordFirst)
	}
}

// readBits reads a bit range: discrete input or coil selected by kind.
func (d *driver) readBits(addr, quantity uint16, kind string) ([]bool, error) {
	if kind == modiconDI {
		return d.client.ReadDiscreteInputs(addr, quantity)
	}
	return d.client.ReadCoils(addr, quantity)
}

// fallbackBlock re-reads a failed block point by point.
func (d *driver) fallbackBlock(blk []readPlan, out []iot_points.Data) {
	for _, p := range blk {
		out[p.index] = d.readOne(p.point)
	}
}

// readOne reads a single point, turning failure into a marked Data.
func (d *driver) readOne(p iot_points.Point) iot_points.Data {
	dd, err := d.readPoint(p)
	if err != nil {
		return iot_points.Data{Name: p.Name, Error: err.Error()}
	}
	return dd
}

// lowWordFirst reports whether the client word order is LOW_WORD_FIRST.
// ReadRegisters applies only per-word endianness, so batch slices of multi-register points need word reversal.
func (r *RetryableModbusClient) lowWordFirst() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.wordOrder == modbus.LOW_WORD_FIRST
}

// wordsToData decodes a point's word slice, matching readPoint's per-type semantics.
func wordsToData(words []uint16, p iot_points.Point, typ string, lowWordFirst bool) iot_points.Data {
	var val interface{}
	var raw float64
	switch typ {
	case iot_points.TypeBool:
		b := words[0]&1 != 0
		val = b
		if b {
			raw = 1
		}
	case iot_points.TypeInt16:
		val = int16(words[0])
		raw = float64(int16(words[0]))
	case iot_points.TypeUint16, "":
		val = words[0]
		raw = float64(words[0])
	default:
		w := words
		if p.Endian != "" {
			w = applyEndian(w, p.Endian)
		} else if lowWordFirst {
			w = applyEndian(w, "CDAB") // reverse words to ABCD order
		}
		val, raw = decodeModbusWords(typ, w)
	}
	if (p.Scale != 0 || p.Offset != 0) && typ != iot_points.TypeBool {
		val = iot_points.ApplyScale(raw, p)
	}
	return iot_points.Data{Name: p.Name, Value: val, Timestamp: time.Now().UnixNano()}
}

// bitToData wraps a bit value into Data, matching readPoint's bit-area semantics.
func bitToData(b bool, p iot_points.Point, typ string) iot_points.Data {
	var val interface{} = b
	var raw float64
	if b {
		raw = 1
	}
	if (p.Scale != 0 || p.Offset != 0) && typ != iot_points.TypeBool {
		val = iot_points.ApplyScale(raw, p)
	}
	return iot_points.Data{Name: p.Name, Value: val, Timestamp: time.Now().UnixNano()}
}

// WritePoints writes by Point.Addr(Modicon) + Type. Any failure returns error immediately. DI/IR read-only rejects writes.
func (d *driver) WritePoints(points []iot_points.Point) error {
	for _, p := range points {
		if err := d.writePoint(p); err != nil {
			return err
		}
	}
	return nil
}

// readPoint reads single point. Type determines library method and register count; Scale/Offset does engineering conversion.
func (d *driver) readPoint(p iot_points.Point) (iot_points.Data, error) {
	regType, addr, kind, err := parseModiconAddr(p.Addr)
	if err != nil {
		return iot_points.Data{}, err
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	var raw float64
	var val interface{}
	switch {
	case typ == iot_points.TypeBool || kind == modiconCoil || kind == modiconDI:
		b, err := d.readBool(addr, kind, regType)
		if err != nil {
			return iot_points.Data{}, err
		}
		val = b
		if b {
			raw = 1
		}
	case typ == iot_points.TypeUint16 || typ == iot_points.TypeInt16 || typ == "":
		v, err := d.client.ReadRegister(addr, regType)
		if err != nil {
			return iot_points.Data{}, err
		}
		if typ == iot_points.TypeInt16 {
			val = int16(v)
			raw = float64(int16(v))
		} else {
			val = v
			raw = float64(v)
		}
	case typ == iot_points.TypeUint32 || typ == iot_points.TypeInt32 || typ == iot_points.TypeFloat32:
		if p.Endian != "" {
			// Point-level endian: decode raw word sequence by Endian reordering
			words, err := d.client.ReadRegisters(addr, 2, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			val, raw = decodeModbusWords(typ, applyEndian(words, p.Endian))
		} else {
			v, err := d.client.ReadUint32(addr, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			if typ == iot_points.TypeFloat32 {
				val = math.Float32frombits(v)
			} else if typ == iot_points.TypeInt32 {
				val = int32(v)
			} else {
				val = v
			}
			raw = float64(toFloat64(val))
		}
	case typ == iot_points.TypeUint64 || typ == iot_points.TypeInt64 || typ == iot_points.TypeFloat64:
		if p.Endian != "" {
			words, err := d.client.ReadRegisters(addr, 4, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			val, raw = decodeModbusWords(typ, applyEndian(words, p.Endian))
		} else {
			v, err := d.client.ReadUint64(addr, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			if typ == iot_points.TypeFloat64 {
				val = math.Float64frombits(v)
			} else if typ == iot_points.TypeInt64 {
				val = int64(v)
			} else {
				val = v
			}
			raw = float64(toFloat64(val))
		}
	default:
		return iot_points.Data{}, fmt.Errorf("unsupported modbus type %q", p.Type)
	}
	// Engineering conversion (BOOL no conversion)
	if (p.Scale != 0 || p.Offset != 0) && typ != iot_points.TypeBool {
		val = iot_points.ApplyScale(raw, p)
	}
	return iot_points.Data{Name: p.Name, Value: val, Timestamp: time.Now().UnixNano()}, nil
}

// readBool reads bit: coil/discrete input select method by kind; register area (HR/IR) BOOL takes register bit0.
func (d *driver) readBool(addr uint16, kind string, regType modbus.RegType) (bool, error) {
	switch kind {
	case modiconDI:
		return d.client.ReadDiscreteInput(addr)
	case modiconCoil:
		return d.client.ReadCoil(addr)
	default:
		v, err := d.client.ReadRegister(addr, regType)
		if err != nil {
			return false, err
		}
		return v&1 != 0, nil
	}
}

// toFloat64 converts numeric to float64 (for Scale raw value).
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case uint32:
		return float64(n)
	case int32:
		return float64(n)
	case float32:
		return float64(n)
	case uint64:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case uint16:
		return float64(n)
	case int16:
		return float64(n)
	}
	return 0
}

// applyEndian reorders word sequence by point byte order (device original order ABCD big-endian high-word-first).
// CDAB=word swap, BADC=word-inner-byte swap, DCBA=both; four transforms are involutions, same function for encode/decode.
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

// decodeModbusWords big-endian word sequence (ABCD) -> unified type value and raw float.
func decodeModbusWords(typ string, w []uint16) (interface{}, float64) {
	u32 := uint32(w[0])<<16 | uint32(w[1])
	switch typ {
	case iot_points.TypeInt32:
		v := int32(u32)
		return v, float64(v)
	case iot_points.TypeUint32:
		return u32, float64(u32)
	case iot_points.TypeFloat32:
		v := math.Float32frombits(u32)
		return v, float64(v)
	}
	u64 := uint64(w[0])<<48 | uint64(w[1])<<32 | uint64(w[2])<<16 | uint64(w[3])
	switch typ {
	case iot_points.TypeInt64:
		v := int64(u64)
		return v, float64(v)
	case iot_points.TypeUint64:
		return u64, float64(u64)
	case iot_points.TypeFloat64:
		v := math.Float64frombits(u64)
		return v, v
	}
	return nil, 0
}

// encodeModbusWords unified type string value -> big-endian word sequence (ABCD).
func encodeModbusWords(typ, value string) ([]uint16, error) {
	switch typ {
	case iot_points.TypeInt32, iot_points.TypeUint32:
		var v uint64
		if typ == iot_points.TypeInt32 {
			s, err := strconv.ParseInt(value, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("parse int32 value %q: %w", value, err)
			}
			v = uint64(uint32(s))
		} else {
			u, err := strconv.ParseUint(value, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("parse uint32 value %q: %w", value, err)
			}
			v = u
		}
		return []uint16{uint16(v >> 16), uint16(v)}, nil
	case iot_points.TypeFloat32:
		f, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return nil, fmt.Errorf("parse float32 value %q: %w", value, err)
		}
		v := math.Float32bits(float32(f))
		return []uint16{uint16(v >> 16), uint16(v)}, nil
	case iot_points.TypeInt64, iot_points.TypeUint64:
		var v uint64
		if typ == iot_points.TypeInt64 {
			s, err := strconv.ParseInt(value, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("parse int64 value %q: %w", value, err)
			}
			v = uint64(s)
		} else {
			u, err := strconv.ParseUint(value, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("parse uint64 value %q: %w", value, err)
			}
			v = u
		}
		return []uint16{uint16(v >> 48), uint16(v >> 32), uint16(v >> 16), uint16(v)}, nil
	case iot_points.TypeFloat64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("parse float64 value %q: %w", value, err)
		}
		v := math.Float64bits(f)
		return []uint16{uint16(v >> 48), uint16(v >> 32), uint16(v >> 16), uint16(v)}, nil
	}
	return nil, fmt.Errorf("unsupported endian encode type %q", typ)
}

// writePoint writes single point. Register writes limited to HR; coil writes limited to Coil.
func (d *driver) writePoint(p iot_points.Point) error {
	_, addr, kind, err := parseModiconAddr(p.Addr)
	if err != nil {
		return err
	}
	if kind == modiconDI || kind == modiconIR {
		return fmt.Errorf("modbus %s addr %s is read-only", kind, p.Addr)
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	switch {
	case typ == iot_points.TypeBool || kind == modiconCoil:
		// BOOL write only supports coil area
		if kind != modiconCoil {
			return fmt.Errorf("modbus BOOL write only supports Coil(00001) addr, got %s", p.Addr)
		}
		b, err := byteToBool(p.Value)
		if err != nil {
			return fmt.Errorf("parse bool value %q: %w", p.Value, err)
		}
		return d.client.WriteCoil(addr, b)
	case typ == iot_points.TypeUint16 || typ == iot_points.TypeInt16 || typ == "":
		if typ == iot_points.TypeInt16 {
			v, err := strconv.ParseInt(p.Value, 0, 16)
			if err != nil {
				return fmt.Errorf("parse int16 value %q: %w", p.Value, err)
			}
			return d.client.WriteRegister(addr, uint16(v))
		}
		v, err := strconv.ParseUint(p.Value, 0, 16)
		if err != nil {
			return fmt.Errorf("parse uint16 value %q: %w", p.Value, err)
		}
		return d.client.WriteRegister(addr, uint16(v))
	default:
		// Multi-register type: when point-level Endian, encode as word sequence and write by byte order
		if p.Endian != "" {
			words, err := encodeModbusWords(typ, p.Value)
			if err != nil {
				return err
			}
			return d.client.WriteRegisters(addr, applyEndian(words, p.Endian))
		}
		switch typ {
		case iot_points.TypeUint32, iot_points.TypeInt32:
			if typ == iot_points.TypeInt32 {
				v, err := strconv.ParseInt(p.Value, 0, 32)
				if err != nil {
					return fmt.Errorf("parse int32 value %q: %w", p.Value, err)
				}
				return d.client.WriteUint32(addr, uint32(v))
			}
			v, err := strconv.ParseUint(p.Value, 0, 32)
			if err != nil {
				return fmt.Errorf("parse uint32 value %q: %w", p.Value, err)
			}
			return d.client.WriteUint32(addr, uint32(v))
		case iot_points.TypeUint64, iot_points.TypeInt64:
			if typ == iot_points.TypeInt64 {
				v, err := strconv.ParseInt(p.Value, 0, 64)
				if err != nil {
					return fmt.Errorf("parse int64 value %q: %w", p.Value, err)
				}
				return d.client.WriteUint64(addr, uint64(v))
			}
			v, err := strconv.ParseUint(p.Value, 0, 64)
			if err != nil {
				return fmt.Errorf("parse uint64 value %q: %w", p.Value, err)
			}
			return d.client.WriteUint64(addr, v)
		case iot_points.TypeFloat32:
			f, err := strconv.ParseFloat(p.Value, 32)
			if err != nil {
				return fmt.Errorf("parse float32 value %q: %w", p.Value, err)
			}
			return d.client.WriteFloat32(addr, float32(f))
		case iot_points.TypeFloat64:
			f, err := strconv.ParseFloat(p.Value, 64)
			if err != nil {
				return fmt.Errorf("parse float64 value %q: %w", p.Value, err)
			}
			return d.client.WriteFloat64(addr, f)
		default:
			return fmt.Errorf("unsupported modbus type %q", p.Type)
		}
	}
}

// parseModiconAddr parses Modicon traditional address (1-based) to protocol address (0-based) + type.
//
//	00001-09999   -> Coil          (function code 01/05/0F)
//	10001-19999   -> Discrete Input(function code 02, read-only)
//	30001-39999   -> Input Register(function code 04, read-only)
//	40001-49999   -> Holding Register(function code 03/06/10)
//	400001-465535 -> Holding Register extended (6 digits)
func parseModiconAddr(addr string) (regType modbus.RegType, protocolAddr uint16, kind string, err error) {
	n, perr := strconv.ParseUint(strings.TrimSpace(addr), 10, 32)
	if perr != nil {
		return 0, 0, "", fmt.Errorf("invalid modicon addr %q: %w", addr, perr)
	}
	switch {
	case n >= 1 && n <= 9999:
		kind = modiconCoil
		protocolAddr = uint16(n - 1)
	case n >= 10001 && n <= 19999:
		kind = modiconDI
		protocolAddr = uint16(n - 10001)
	case n >= 30001 && n <= 39999:
		kind = modiconIR
		regType = modbus.INPUT_REGISTER
		protocolAddr = uint16(n - 30001)
	case n >= 40001 && n <= 49999:
		kind = modiconHR
		regType = modbus.HOLDING_REGISTER
		protocolAddr = uint16(n - 40001)
	case n >= 400001 && n <= 465535:
		kind = modiconHR
		regType = modbus.HOLDING_REGISTER
		protocolAddr = uint16(n - 400001)
	default:
		return 0, 0, "", fmt.Errorf("invalid modicon addr %q (must be 0xxxx/1xxxx/3xxxx/4xxxx)", addr)
	}
	return regType, protocolAddr, kind, nil
}
