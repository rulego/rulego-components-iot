package s7client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakePLC serves reads from per-area byte arrays and counts requests, so merging,
// buffer slicing and the fallback path are testable without a real PLC.
type fakePLC struct {
	db    map[int][]byte // dbNumber -> bytes
	m     []byte
	i     []byte
	q     []byte
	reads int   // request count
	sizes []int // bytes per request
	// failDBRange fails multi-byte DB reads, simulating a PLC that refuses a span
	// (e.g. it crosses a protected offset) while single points still read.
	failDBRange int
}

func newFakePLC() *fakePLC {
	return &fakePLC{db: map[int][]byte{}, m: make([]byte, 256), i: make([]byte, 256), q: make([]byte, 256)}
}

func (f *fakePLC) serve(src []byte, start, size int, buf []byte) error {
	f.reads++
	f.sizes = append(f.sizes, size)
	if start < 0 || start+size > len(src) {
		return errors.New("address out of range")
	}
	copy(buf, src[start:start+size])
	return nil
}

func (f *fakePLC) AGReadDB(dbNumber, start, size int, buf []byte) error {
	if f.failDBRange > 0 && size > f.failDBRange {
		f.reads++
		f.sizes = append(f.sizes, size)
		return errors.New("range refused")
	}
	src, ok := f.db[dbNumber]
	if !ok {
		f.reads++
		return errors.New("no such DB")
	}
	return f.serve(src, start, size, buf)
}

func (f *fakePLC) AGReadMB(start, size int, buf []byte) error { return f.serve(f.m, start, size, buf) }
func (f *fakePLC) AGReadEB(start, size int, buf []byte) error { return f.serve(f.i, start, size, buf) }
func (f *fakePLC) AGReadAB(start, size int, buf []byte) error { return f.serve(f.q, start, size, buf) }

// fillDB seeds DB1 with deterministic bytes.
func fillDB(f *fakePLC, db int, n int) {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	f.db[db] = b
}

// mixedPoints spans types and areas on near-contiguous offsets so blocks actually merge.
func mixedPoints() []Point {
	return []Point{
		{Name: "i0", Area: "DB", DbNumber: 1, Address: 0, Type: "INT"},
		{Name: "i2", Area: "DB", DbNumber: 1, Address: 2, Type: "INT"},
		{Name: "d4", Area: "DB", DbNumber: 1, Address: 4, Type: "DINT"},
		{Name: "r8", Area: "DB", DbNumber: 1, Address: 8, Type: "REAL"},
		{Name: "b12", Area: "DB", DbNumber: 1, Address: 12, Type: "BYTE"},
		{Name: "bit13_0", Area: "DB", DbNumber: 1, Address: 13, Type: "BOOL", BitOffset: 0},
		{Name: "bit13_3", Area: "DB", DbNumber: 1, Address: 13, Type: "BOOL", BitOffset: 3},
		{Name: "arr14", Area: "DB", DbNumber: 1, Address: 14, Type: "INT", Count: 3},
		{Name: "m0", Area: "M", Address: 0, Type: "WORD"},
		{Name: "q4", Area: "Q", Address: 4, Type: "BYTE"},
	}
}

// perPointBaseline reads each point in its own request (the pre-optimization path).
func perPointBaseline(client s7Reader, pts []Point) []Data {
	out := make([]Data, len(pts))
	for i, p := range pts {
		w, _ := pointWidth(p)
		_, _ = readSingle(client, readPlan{index: i, point: p, start: p.Address, width: w}, out, nil)
	}
	return out
}

// 批读结果必须与逐点读逐字段一致 —— 这是"优化不改变行为"的机械保证。
func TestReadBlocks_EquivalentToPerPoint(t *testing.T) {
	pts := mixedPoints()

	fb := newFakePLC()
	fillDB(fb, 1, 64)
	want := perPointBaseline(fb, pts)
	perPointReads := fb.reads

	fa := newFakePLC()
	fillDB(fa, 1, 64)
	got := make([]Data, len(pts))
	fail, _ := readBlocks(fa, pts, got, 240, nil)

	assert.Equal(t, 0, fail)
	assert.Equal(t, len(want), len(got))
	for i := range want {
		assert.Equal(t, want[i].Name, got[i].Name, "第 %d 条名字", i)
		assert.Equal(t, want[i].Quality, got[i].Quality, "点位 %s 质量", want[i].Name)
		assert.Equal(t, want[i].Value, got[i].Value, "点位 %s 值不一致", want[i].Name)
		assert.IsType(t, want[i].Value, got[i].Value, "点位 %s 值类型变了", want[i].Name)
		assert.Equal(t, want[i].Address, got[i].Address, "点位 %s 地址", want[i].Name)
	}
	// 请求数必须真的降下来:DB1 一块 + M 一块 + Q 一块 = 3。
	assert.Equal(t, 3, fa.reads, "10 个点位应合并成 3 次请求, 实际 %d", fa.reads)
	assert.Equal(t, 10, perPointReads, "基线应为逐点 10 次")
}

// 同字节内多个 BOOL 共享一次读取,且各自按 bitOffset 取到正确的位。
func TestReadBlocks_BoolsShareByte(t *testing.T) {
	f := newFakePLC()
	f.db[1] = []byte{0b00001001} // bit0=1, bit3=1, 其余 0
	pts := []Point{
		{Name: "b0", Area: "DB", DbNumber: 1, Address: 0, Type: "BOOL", BitOffset: 0},
		{Name: "b1", Area: "DB", DbNumber: 1, Address: 0, Type: "BOOL", BitOffset: 1},
		{Name: "b3", Area: "DB", DbNumber: 1, Address: 0, Type: "BOOL", BitOffset: 3},
	}
	out := make([]Data, len(pts))
	fail, _ := readBlocks(f, pts, out, 240, nil)

	assert.Equal(t, 0, fail)
	assert.Equal(t, 1, f.reads, "同字节 3 个 BOOL 只需 1 次读取")
	assert.Equal(t, true, out[0].Value)
	assert.Equal(t, false, out[1].Value)
	assert.Equal(t, true, out[2].Value)
}

// 块读被拒时回退逐点,不能丢掉整块。
func TestReadBlocks_FallsBackOnBlockFailure(t *testing.T) {
	f := newFakePLC()
	fillDB(f, 1, 64)
	f.failDBRange = 2 // 超过 2 字节的 DB 范围读一律拒绝

	pts := []Point{
		{Name: "a", Area: "DB", DbNumber: 1, Address: 0, Type: "INT"},
		{Name: "b", Area: "DB", DbNumber: 1, Address: 2, Type: "INT"},
		{Name: "c", Area: "DB", DbNumber: 1, Address: 4, Type: "INT"},
	}
	out := make([]Data, len(pts))
	fail, _ := readBlocks(f, pts, out, 240, nil)

	assert.Equal(t, 0, fail, "回退逐点后应全部成功")
	for i := range pts {
		assert.Equal(t, "good", out[i].Quality, "点位 %s", pts[i].Name)
	}
}

// 未知类型/非法区域不参与读取,直接标 bad(不能拿去读出垃圾)。
func TestReadBlocks_BadPointsNotRead(t *testing.T) {
	f := newFakePLC()
	fillDB(f, 1, 16)
	pts := []Point{
		{Name: "ok", Area: "DB", DbNumber: 1, Address: 0, Type: "INT"},
		{Name: "badType", Area: "DB", DbNumber: 1, Address: 2, Type: "NOPE"},
		{Name: "badArea", Area: "ZZ", Address: 0, Type: "INT"},
	}
	out := make([]Data, len(pts))
	fail, _ := readBlocks(f, pts, out, 240, nil)

	assert.Equal(t, 2, fail)
	assert.Equal(t, "good", out[0].Quality)
	assert.Equal(t, "bad", out[1].Quality)
	assert.Equal(t, "bad", out[2].Quality)
	assert.Equal(t, "badType", out[1].Name, "坏点位的槽位仍须属于原点位")
}

// 结果顺序与点位顺序一致,即使分组打乱了读取顺序。
func TestReadBlocks_PreservesOrder(t *testing.T) {
	f := newFakePLC()
	fillDB(f, 1, 32)
	fillDB(f, 2, 32)
	pts := []Point{
		{Name: "m", Area: "M", Address: 0, Type: "BYTE"},
		{Name: "db2", Area: "DB", DbNumber: 2, Address: 0, Type: "INT"},
		{Name: "db1", Area: "DB", DbNumber: 1, Address: 0, Type: "INT"},
		{Name: "q", Area: "Q", Address: 0, Type: "BYTE"},
	}
	out := make([]Data, len(pts))
	readBlocks(f, pts, out, 240, nil)

	for i := range pts {
		assert.Equal(t, pts[i].Name, out[i].Name, "第 %d 条错位", i)
	}
}

// 小 PDU 下必须切块,且每块不超上限。
func TestReadBlocks_RespectsPDULimit(t *testing.T) {
	f := newFakePLC()
	fillDB(f, 1, 256)
	var pts []Point
	for i := 0; i < 40; i++ {
		pts = append(pts, Point{Name: itoa(i), Area: "DB", DbNumber: 1, Address: i * 2, Type: "INT"})
	}
	out := make([]Data, len(pts))
	fail, _ := readBlocks(f, pts, out, 60, nil) // 可用载荷 60-18=42 字节

	assert.Equal(t, 0, fail)
	assert.True(t, f.reads > 1, "小 PDU 下应切成多块")
	for i, s := range f.sizes {
		assert.LessOrEqual(t, s, 42, "第 %d 次请求 %d 字节超上限", i, s)
	}
}
