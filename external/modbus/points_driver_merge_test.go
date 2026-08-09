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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/simonvetter/modbus"
	"github.com/stretchr/testify/assert"
)

// --- chunking logic (pure functions) ---

// mkPlans builds address-sorted readPlans from points, same way ReadPoints plans them.
func mkPlans(t *testing.T, points []iot_points.Point) []readPlan {
	t.Helper()
	ps := make([]readPlan, 0, len(points))
	for i, p := range points {
		regType, addr, kind, err := parseModiconAddr(p.Addr)
		assert.Nil(t, err, "addr %s", p.Addr)
		typ := strings.ToUpper(strings.TrimSpace(p.Type))
		w, ok := pointRegWidth(typ, kind)
		assert.True(t, ok, "type %s should be plannable", p.Type)
		ps = append(ps, readPlan{point: p, index: i, addr: addr, width: w, typ: typ, kind: kind, regType: regType})
	}
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].addr < ps[j].addr })
	return ps
}

// blockSpan returns a block's start address and register/bit quantity.
func blockSpan(blk []readPlan) (uint16, uint16) {
	start := uint32(blk[0].addr)
	var end uint32
	for _, p := range blk {
		if e := uint32(p.addr) + uint32(p.width); e > end {
			end = e
		}
	}
	return uint16(start), uint16(end - start)
}

// TestChunkPlans_Contiguous: contiguous addresses merge into 1 block.
func TestChunkPlans_Contiguous(t *testing.T) {
	var pts []iot_points.Point
	for i := 0; i < 20; i++ {
		pts = append(pts, iot_points.Point{Name: fmt.Sprintf("p%d", i), Addr: fmt.Sprintf("%d", 40001+i), Type: iot_points.TypeUint16})
	}
	blocks := chunkPlans(mkPlans(t, pts))
	assert.Equal(t, 1, len(blocks))
	start, qty := blockSpan(blocks[0])
	assert.Equal(t, uint16(0), start)
	assert.Equal(t, uint16(20), qty)
}

// TestChunkPlans_GapWithinTolerance: hole <= modbusMergeGap still merges, and reads over the hole.
func TestChunkPlans_GapWithinTolerance(t *testing.T) {
	// 40001(addr0) and 40009(addr8): gap exactly 8 (end=1, a=8, a <= end+8)
	pts := []iot_points.Point{
		{Name: "a", Addr: "40001", Type: iot_points.TypeUint16},
		{Name: "b", Addr: "40009", Type: iot_points.TypeUint16},
	}
	blocks := chunkPlans(mkPlans(t, pts))
	assert.Equal(t, 1, len(blocks))
	start, qty := blockSpan(blocks[0])
	assert.Equal(t, uint16(0), start)
	assert.Equal(t, uint16(9), qty) // reads 9 registers, discards the hole
}

// TestChunkPlans_GapExceedsTolerance: hole > modbusMergeGap splits blocks.
func TestChunkPlans_GapExceedsTolerance(t *testing.T) {
	// 40001(addr0) and 40011(addr10): end=1, a=10 > 1+8 -> split
	pts := []iot_points.Point{
		{Name: "a", Addr: "40001", Type: iot_points.TypeUint16},
		{Name: "b", Addr: "40011", Type: iot_points.TypeUint16},
	}
	blocks := chunkPlans(mkPlans(t, pts))
	assert.Equal(t, 2, len(blocks))
	_, q0 := blockSpan(blocks[0])
	_, q1 := blockSpan(blocks[1])
	assert.Equal(t, uint16(1), q0)
	assert.Equal(t, uint16(1), q1)
}

// TestChunkPlans_RegLimit: contiguous points exceeding 125 registers split; each block <= 125.
func TestChunkPlans_RegLimit(t *testing.T) {
	var pts []iot_points.Point
	for i := 0; i < 300; i++ {
		pts = append(pts, iot_points.Point{Name: fmt.Sprintf("p%d", i), Addr: fmt.Sprintf("%d", 40001+i), Type: iot_points.TypeUint16})
	}
	blocks := chunkPlans(mkPlans(t, pts))
	assert.Equal(t, 3, len(blocks)) // 125 + 125 + 50
	total := 0
	for _, b := range blocks {
		_, qty := blockSpan(b)
		assert.LessOrEqual(t, int(qty), modbusMaxRegsPerRead)
		total += len(b)
	}
	assert.Equal(t, 300, total)
}

// TestChunkPlans_BitLimit: coil area uses the 2000-bit limit, not 125.
func TestChunkPlans_BitLimit(t *testing.T) {
	var pts []iot_points.Point
	for i := 0; i < 300; i++ {
		pts = append(pts, iot_points.Point{Name: fmt.Sprintf("c%d", i), Addr: fmt.Sprintf("%d", 1+i), Type: iot_points.TypeBool})
	}
	blocks := chunkPlans(mkPlans(t, pts))
	assert.Equal(t, 1, len(blocks)) // 300 bits well under 2000
	_, qty := blockSpan(blocks[0])
	assert.Equal(t, uint16(300), qty)
}

// TestPointRegWidth: multi-register types occupy correct width; bit area always 1; unsupported type rejected.
func TestPointRegWidth(t *testing.T) {
	cases := []struct {
		typ, kind string
		want      uint16
		ok        bool
	}{
		{iot_points.TypeUint16, modiconHR, 1, true},
		{iot_points.TypeInt16, modiconHR, 1, true},
		{"", modiconHR, 1, true},
		{iot_points.TypeBool, modiconHR, 1, true},
		{iot_points.TypeFloat32, modiconHR, 2, true},
		{iot_points.TypeUint32, modiconHR, 2, true},
		{iot_points.TypeInt32, modiconIR, 2, true},
		{iot_points.TypeFloat64, modiconHR, 4, true},
		{iot_points.TypeInt64, modiconHR, 4, true},
		{iot_points.TypeUint64, modiconHR, 4, true},
		{iot_points.TypeUint16, modiconCoil, 1, true}, // bit area ignores type
		{iot_points.TypeFloat32, modiconDI, 1, true},
		{"STRING", modiconHR, 0, false},
	}
	for _, c := range cases {
		got, ok := pointRegWidth(c.typ, c.kind)
		assert.Equal(t, c.ok, ok, "typ=%s kind=%s", c.typ, c.kind)
		assert.Equal(t, c.want, got, "typ=%s kind=%s", c.typ, c.kind)
	}
}

// TestChunkPlans_MultiRegWidthSpan: block span counts each point's register width, not just start addresses.
func TestChunkPlans_MultiRegWidthSpan(t *testing.T) {
	// FLOAT64@40001 occupies addr 0..3, UINT16@40005 is addr 4 -> contiguous, span 5
	pts := []iot_points.Point{
		{Name: "f64", Addr: "40001", Type: iot_points.TypeFloat64},
		{Name: "u16", Addr: "40005", Type: iot_points.TypeUint16},
	}
	blocks := chunkPlans(mkPlans(t, pts))
	assert.Equal(t, 1, len(blocks))
	start, qty := blockSpan(blocks[0])
	assert.Equal(t, uint16(0), start)
	assert.Equal(t, uint16(5), qty)

	// 62 FLOAT32 = 124 registers, +1 more FLOAT32 would be 126 > 125 -> split
	var wide []iot_points.Point
	for i := 0; i < 63; i++ {
		wide = append(wide, iot_points.Point{Name: fmt.Sprintf("f%d", i), Addr: fmt.Sprintf("%d", 40001+i*2), Type: iot_points.TypeFloat32})
	}
	blocks = chunkPlans(mkPlans(t, wide))
	assert.Equal(t, 2, len(blocks))
	_, q0 := blockSpan(blocks[0])
	assert.Equal(t, uint16(124), q0) // 62 points * 2 regs
	assert.Equal(t, 62, len(blocks[0]))
	assert.Equal(t, 1, len(blocks[1]))
}

// TestPlanGroups_SeparatesRegTypeAndKind: different regType/kind never merge into one block.
func TestPlanGroups_SeparatesRegTypeAndKind(t *testing.T) {
	d := &driver{}
	pts := []iot_points.Point{
		{Name: "hr", Addr: "40001", Type: iot_points.TypeUint16},
		{Name: "ir", Addr: "30001", Type: iot_points.TypeUint16},
		{Name: "coil", Addr: "00001", Type: iot_points.TypeBool},
		{Name: "di", Addr: "10001", Type: iot_points.TypeBool},
		{Name: "hr2", Addr: "40002", Type: iot_points.TypeUint16},
	}
	out := make([]iot_points.Data, len(pts))
	groups, keys := d.planGroups(pts, out)
	assert.Equal(t, 4, len(keys)) // HR / IR / coil / DI
	assert.Equal(t, 4, len(groups))
	for _, k := range keys {
		kinds := map[string]bool{}
		regTypes := map[modbus.RegType]bool{}
		for _, p := range groups[k] {
			kinds[p.kind] = true
			regTypes[p.regType] = true
		}
		assert.Equal(t, 1, len(kinds), "group %s mixes kinds", k)
		assert.Equal(t, 1, len(regTypes), "group %s mixes regTypes", k)
	}
	// The 2 HR points land in one group, so they can merge
	hrKey := fmt.Sprintf("%d/%s", modbus.HOLDING_REGISTER, modiconHR)
	assert.Equal(t, 2, len(groups[hrKey]))
}

// --- integration: batch vs per-point equivalence via in-memory modbus server ---

// countingHandler is testHandler plus request counters and injectable bad addresses.
type countingHandler struct {
	mu       sync.Mutex
	coils    map[uint16]bool
	di       map[uint16]bool
	hr       map[uint16]uint16
	ir       map[uint16]uint16
	badHR    map[uint16]bool // addresses that return an exception
	requests int32           // read request count
}

func newCountingHandler() *countingHandler {
	return &countingHandler{
		coils: map[uint16]bool{}, di: map[uint16]bool{},
		hr: map[uint16]uint16{}, ir: map[uint16]uint16{}, badHR: map[uint16]bool{},
	}
}

func (h *countingHandler) reqs() int  { return int(atomic.LoadInt32(&h.requests)) }
func (h *countingHandler) resetReqs() { atomic.StoreInt32(&h.requests, 0) }
func (h *countingHandler) countRead() { atomic.AddInt32(&h.requests, 1) }

func (h *countingHandler) HandleCoils(req *modbus.CoilsRequest) ([]bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.IsWrite {
		for i, v := range req.Args {
			h.coils[req.Addr+uint16(i)] = v
		}
		return nil, nil
	}
	h.countRead()
	res := make([]bool, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.coils[req.Addr+i])
	}
	return res, nil
}

func (h *countingHandler) HandleDiscreteInputs(req *modbus.DiscreteInputsRequest) ([]bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.countRead()
	res := make([]bool, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.di[req.Addr+i])
	}
	return res, nil
}

func (h *countingHandler) HandleHoldingRegisters(req *modbus.HoldingRegistersRequest) ([]uint16, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.IsWrite {
		for i, v := range req.Args {
			h.hr[req.Addr+uint16(i)] = v
		}
		return nil, nil
	}
	h.countRead()
	// Any bad address inside the requested range fails the whole request (real device behavior)
	for i := uint16(0); i < req.Quantity; i++ {
		if h.badHR[req.Addr+i] {
			return nil, modbus.ErrIllegalDataAddress
		}
	}
	res := make([]uint16, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.hr[req.Addr+i])
	}
	return res, nil
}

func (h *countingHandler) HandleInputRegisters(req *modbus.InputRegistersRequest) ([]uint16, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.countRead()
	res := make([]uint16, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.ir[req.Addr+i])
	}
	return res, nil
}

// newCountingDriver starts an in-memory server with the given word order and returns a connected driver.
func newCountingDriver(t *testing.T, h *countingHandler, port string, wordOrder modbus.WordOrder) *driver {
	t.Helper()
	server, err := modbus.NewServer(&modbus.ServerConfiguration{URL: "tcp://127.0.0.1:" + port}, h)
	assert.Nil(t, err)
	assert.Nil(t, server.Start())
	t.Cleanup(func() { _ = server.Stop() })

	client, err := modbus.NewClient(&modbus.ClientConfiguration{URL: "tcp://127.0.0.1:" + port})
	assert.Nil(t, err)
	assert.Nil(t, client.Open())
	t.Cleanup(func() { _ = client.Close() })

	r := NewRetryableModbusClient(client, 0, nil, nil, 1, modbus.BIG_ENDIAN, wordOrder, nil)
	r.SetEncoding(modbus.BIG_ENDIAN, wordOrder)
	return newDriver(r)
}

// readPerPoint reads points one by one (pre-optimization reference path).
func readPerPoint(d *driver, points []iot_points.Point) []iot_points.Data {
	out := make([]iot_points.Data, 0, len(points))
	for _, p := range points {
		out = append(out, d.readOne(p))
	}
	return out
}

// fillDeterministic prefills registers with values that never decode to NaN.
func fillDeterministic(h *countingHandler) {
	for i := uint16(0); i < 60; i++ {
		h.hr[i] = 0x1000 + i*0x111
		h.ir[i] = 0x2000 + i*0x101
	}
	for i := uint16(0); i < 40; i++ {
		h.coils[i] = i%3 == 0
		h.di[i] = i%2 == 0
	}
}

// equivalencePoints covers all types/areas/endian/scale on contiguous-ish addresses so blocks actually merge.
func equivalencePoints() []iot_points.Point {
	return []iot_points.Point{
		{Name: "u16", Addr: "40001", Type: iot_points.TypeUint16},
		{Name: "i16", Addr: "40002", Type: iot_points.TypeInt16},
		{Name: "deftyp", Addr: "40003"}, // empty type -> uint16
		{Name: "boolhr", Addr: "40004", Type: iot_points.TypeBool},
		{Name: "u32", Addr: "40005", Type: iot_points.TypeUint32},
		{Name: "i32", Addr: "40007", Type: iot_points.TypeInt32},
		{Name: "f32", Addr: "40009", Type: iot_points.TypeFloat32},
		{Name: "f32cdab", Addr: "40011", Type: iot_points.TypeFloat32, Endian: "CDAB"},
		{Name: "f32badc", Addr: "40013", Type: iot_points.TypeFloat32, Endian: "BADC"},
		{Name: "f32dcba", Addr: "40015", Type: iot_points.TypeFloat32, Endian: "DCBA"},
		{Name: "u64", Addr: "40017", Type: iot_points.TypeUint64},
		{Name: "i64", Addr: "40021", Type: iot_points.TypeInt64},
		{Name: "f64", Addr: "40025", Type: iot_points.TypeFloat64},
		{Name: "f64cdab", Addr: "40029", Type: iot_points.TypeFloat64, Endian: "CDAB"},
		{Name: "scaled", Addr: "40033", Type: iot_points.TypeUint16, Scale: 0.1},
		{Name: "scaleoff", Addr: "40034", Type: iot_points.TypeInt16, Scale: 2, Offset: -5},
		{Name: "u32scaled", Addr: "40035", Type: iot_points.TypeUint32, Scale: 0.01},
		{Name: "hole", Addr: "40040", Type: iot_points.TypeUint16}, // gap within tolerance
		{Name: "ir0", Addr: "30001", Type: iot_points.TypeUint16},
		{Name: "ir1", Addr: "30002", Type: iot_points.TypeInt16},
		{Name: "irf32", Addr: "30003", Type: iot_points.TypeFloat32},
		{Name: "coil0", Addr: "00001", Type: iot_points.TypeBool},
		{Name: "coil3", Addr: "00004", Type: iot_points.TypeBool},
		{Name: "coil7", Addr: "00008", Type: iot_points.TypeBool},
		{Name: "di0", Addr: "10001", Type: iot_points.TypeBool},
		{Name: "di2", Addr: "10003", Type: iot_points.TypeBool},
	}
}

// TestBatchEquivalence_HighWordFirst: batch read == per-point read, field by field.
func TestBatchEquivalence_HighWordFirst(t *testing.T) {
	assertBatchEquivalence(t, "5520", modbus.HIGH_WORD_FIRST)
}

// TestBatchEquivalence_LowWordFirst: guards the word-order pitfall — ReadRegisters applies no word order,
// so batch slices of multi-register points must be word-reversed.
func TestBatchEquivalence_LowWordFirst(t *testing.T) {
	assertBatchEquivalence(t, "5521", modbus.LOW_WORD_FIRST)
}

func assertBatchEquivalence(t *testing.T, port string, wo modbus.WordOrder) {
	t.Helper()
	h := newCountingHandler()
	fillDeterministic(h)
	d := newCountingDriver(t, h, port, wo)
	pts := equivalencePoints()

	want := readPerPoint(d, pts)
	perPointReqs := h.reqs()

	h.resetReqs()
	got, err := d.ReadPoints(pts)
	assert.Nil(t, err)
	batchReqs := h.reqs()

	assert.Equal(t, len(want), len(got))
	for i := range want {
		assert.Equal(t, want[i].Name, got[i].Name, "point %d name", i)
		assert.Equal(t, want[i].Error, got[i].Error, "point %s error", want[i].Name)
		assert.Equal(t, want[i].Value, got[i].Value, "point %s value", want[i].Name)
		assert.IsType(t, want[i].Value, got[i].Value, "point %s value type", want[i].Name)
		assert.NotZero(t, got[i].Timestamp, "point %s timestamp", want[i].Name)
	}
	// Order matches input
	for i, p := range pts {
		assert.Equal(t, p.Name, got[i].Name, "output order at %d", i)
	}
	assert.Less(t, batchReqs, perPointReqs)
	t.Logf("wordOrder=%v: per-point=%d requests, batch=%d requests (%.1fx fewer)",
		wo, perPointReqs, batchReqs, float64(perPointReqs)/float64(batchReqs))
}

// TestBatchFallback_BadAddressInBlock: an unreadable address fails the block read;
// fallback per-point keeps every other point's value.
func TestBatchFallback_BadAddressInBlock(t *testing.T) {
	h := newCountingHandler()
	fillDeterministic(h)
	h.badHR[5] = true // addr 5 == 40006
	d := newCountingDriver(t, h, "5522", modbus.HIGH_WORD_FIRST)

	var pts []iot_points.Point
	for i := 0; i < 8; i++ {
		pts = append(pts, iot_points.Point{Name: fmt.Sprintf("p%d", i), Addr: fmt.Sprintf("%d", 40001+i), Type: iot_points.TypeUint16})
	}
	got, err := d.ReadPoints(pts)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(got))

	for i, dd := range got {
		assert.Equal(t, fmt.Sprintf("p%d", i), dd.Name)
		if i == 5 {
			assert.NotEmpty(t, dd.Error, "bad point should carry error")
			assert.Nil(t, dd.Value)
			continue
		}
		assert.Empty(t, dd.Error, "point %d should survive fallback", i)
		assert.Equal(t, h.hr[uint16(i)], dd.Value, "point %d value", i)
	}
}

// TestBatchFallback_AllFailed: every point failing still returns the aggregate error.
func TestBatchFallback_AllFailed(t *testing.T) {
	h := newCountingHandler()
	for i := uint16(0); i < 4; i++ {
		h.badHR[i] = true
	}
	d := newCountingDriver(t, h, "5523", modbus.HIGH_WORD_FIRST)

	pts := []iot_points.Point{
		{Name: "a", Addr: "40001", Type: iot_points.TypeUint16},
		{Name: "b", Addr: "40002", Type: iot_points.TypeUint16},
		{Name: "c", Addr: "40003", Type: iot_points.TypeUint16},
	}
	got, err := d.ReadPoints(pts)
	assert.NotNil(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "all 3 modbus points failed")
}

// TestBatchInvalidAddrAndType: unplannable points still report per-point errors, valid ones still batch.
func TestBatchInvalidAddrAndType(t *testing.T) {
	h := newCountingHandler()
	fillDeterministic(h)
	d := newCountingDriver(t, h, "5524", modbus.HIGH_WORD_FIRST)

	pts := []iot_points.Point{
		{Name: "ok1", Addr: "40001", Type: iot_points.TypeUint16},
		{Name: "badaddr", Addr: "99999", Type: iot_points.TypeUint16},
		{Name: "badtype", Addr: "40002", Type: "STRING"},
		{Name: "ok2", Addr: "40003", Type: iot_points.TypeUint16},
	}
	got, err := d.ReadPoints(pts)
	assert.Nil(t, err)
	assert.Equal(t, 4, len(got))
	assert.Equal(t, h.hr[0], got[0].Value)
	assert.Contains(t, got[1].Error, "invalid modicon addr")
	assert.Contains(t, got[2].Error, "unsupported modbus type")
	assert.Equal(t, h.hr[2], got[3].Value)
}

// TestBatchRequestCount_20Points: 20 contiguous points collapse from 20 requests to 1.
func TestBatchRequestCount_20Points(t *testing.T) {
	h := newCountingHandler()
	fillDeterministic(h)
	d := newCountingDriver(t, h, "5525", modbus.HIGH_WORD_FIRST)

	var pts []iot_points.Point
	for i := 0; i < 20; i++ {
		pts = append(pts, iot_points.Point{Name: fmt.Sprintf("p%d", i), Addr: fmt.Sprintf("%d", 40001+i), Type: iot_points.TypeUint16})
	}

	h.resetReqs()
	perPoint := readPerPoint(d, pts)
	perPointReqs := h.reqs()

	h.resetReqs()
	batch, err := d.ReadPoints(pts)
	assert.Nil(t, err)
	batchReqs := h.reqs()

	assert.Equal(t, 20, perPointReqs)
	assert.Equal(t, 1, batchReqs)
	for i := range perPoint {
		assert.Equal(t, perPoint[i].Value, batch[i].Value, "point %d", i)
	}
	t.Logf("20 contiguous points: per-point=%d requests, batch=%d requests (%dx fewer)",
		perPointReqs, batchReqs, perPointReqs/batchReqs)
}
