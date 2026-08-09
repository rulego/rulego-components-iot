package s7client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPointWidth(t *testing.T) {
	cases := []struct {
		name string
		p    Point
		want int
		ok   bool
	}{
		{"BOOL 占 1 字节(同字节多位共享一次读)", Point{Type: "BOOL"}, 1, true},
		{"BYTE", Point{Type: "BYTE"}, 1, true},
		{"INT", Point{Type: "INT"}, 2, true},
		{"DINT", Point{Type: "DINT"}, 4, true},
		{"REAL", Point{Type: "REAL"}, 4, true},
		{"LREAL", Point{Type: "LREAL"}, 8, true},
		{"INT 数组 count=5", Point{Type: "INT", Count: 5}, 10, true},
		{"count<=0 视为 1", Point{Type: "INT", Count: 0}, 2, true},
		{"STRING 默认 254 + 2 字节头", Point{Type: "STRING"}, 256, true},
		{"STRING 指定长度", Point{Type: "STRING", StringLen: 20}, 22, true},
		{"小写类型也认", Point{Type: "real"}, 4, true},
		{"未知类型", Point{Type: "FLOAT128"}, 0, false},
		{"空类型", Point{Type: ""}, 0, false},
	}
	for _, c := range cases {
		got, ok := pointWidth(c.p)
		assert.Equal(t, c.ok, ok, c.name)
		assert.Equal(t, c.want, got, c.name)
	}
}

// 不同 DB / 不同区不可合并 —— 它们是彼此独立的地址空间。
func TestPlanGroups_SeparatesAreasAndBlocks(t *testing.T) {
	pts := []Point{
		{Name: "a", Area: "DB", DbNumber: 1, Address: 0, Type: "INT"},
		{Name: "b", Area: "DB", DbNumber: 1, Address: 2, Type: "INT"},
		{Name: "c", Area: "DB", DbNumber: 2, Address: 0, Type: "INT"}, // 另一个 DB
		{Name: "d", Area: "M", Address: 0, Type: "BYTE"},
		{Name: "e", Area: "I", Address: 0, Type: "BYTE"},
		{Name: "f", Area: "Q", Address: 0, Type: "BYTE"},
	}
	groups, keys, bad := planGroups(pts)

	assert.Empty(t, bad)
	assert.Equal(t, 5, len(keys), "DB1 / DB2 / M / I / Q 共 5 组")
	assert.Equal(t, 2, len(groups["DB/1"]), "DB1 内两个点位应同组")
	assert.Equal(t, 1, len(groups["DB/2"]))
}

// 非法区域与未知类型进 bad,不参与读取(而不是拿去读出垃圾)。
func TestPlanGroups_CollectsBad(t *testing.T) {
	pts := []Point{
		{Name: "ok", Area: "DB", DbNumber: 1, Address: 0, Type: "INT"},
		{Name: "badArea", Area: "XYZ", Address: 0, Type: "INT"},
		{Name: "badType", Area: "DB", DbNumber: 1, Address: 4, Type: "NOPE"},
	}
	groups, _, bad := planGroups(pts)

	assert.Equal(t, []int{1, 2}, bad)
	assert.Equal(t, 1, len(groups["DB/1"]))
}

// 分组顺序稳定,否则每轮请求顺序漂移,日志与抓包难比对。
func TestPlanGroups_StableKeyOrder(t *testing.T) {
	pts := []Point{
		{Area: "Q", Address: 0, Type: "BYTE"},
		{Area: "DB", DbNumber: 9, Address: 0, Type: "INT"},
		{Area: "M", Address: 0, Type: "BYTE"},
		{Area: "DB", DbNumber: 2, Address: 0, Type: "INT"},
	}
	_, k1, _ := planGroups(pts)
	_, k2, _ := planGroups(pts)
	// 要保证的是确定性(每轮同序),不是某种特定排法。
	assert.Equal(t, k1, k2)
	assert.Equal(t, 4, len(k1))
	// 同类键相邻:字典序下 DB/2 紧邻 DB/9,便于对照日志。
	assert.Equal(t, []string{"A/130", "A/131", "DB/2", "DB/9"}, k1)
}

// 相邻地址合并成一块。
func TestChunkPlans_MergesContiguous(t *testing.T) {
	g := []readPlan{
		{start: 0, width: 2},
		{start: 2, width: 2},
		{start: 4, width: 4},
	}
	blocks := chunkPlans(g, 222)
	assert.Equal(t, 1, len(blocks), "连续地址应合并为一块")
	assert.Equal(t, 3, len(blocks[0]))
}

// 空洞超容差要切块 —— 否则会读回大片无用字节。
func TestChunkPlans_SplitsOnLargeHole(t *testing.T) {
	g := []readPlan{
		{start: 0, width: 2},
		{start: 2 + s7MergeGap + 1, width: 2}, // 超出容差
	}
	blocks := chunkPlans(g, 222)
	assert.Equal(t, 2, len(blocks))
}

// 空洞在容差内仍合并(少读几个字节比多发一次请求便宜)。
func TestChunkPlans_MergesSmallHole(t *testing.T) {
	g := []readPlan{
		{start: 0, width: 2},
		{start: 2 + s7MergeGap, width: 2}, // 恰好在容差边界
	}
	blocks := chunkPlans(g, 222)
	assert.Equal(t, 1, len(blocks))
}

// 超 PDU 可用载荷必须切块。
func TestChunkPlans_SplitsOnPDULimit(t *testing.T) {
	var g []readPlan
	for i := 0; i < 100; i++ {
		g = append(g, readPlan{start: i * 2, width: 2})
	}
	blocks := chunkPlans(g, 50) // 每块最多 50 字节 → 25 个 INT
	assert.True(t, len(blocks) >= 4, "100 个 INT(200 字节)在 50 字节上限下至少 4 块, 实际 %d", len(blocks))
	for i, b := range blocks {
		span := b[len(b)-1].start + b[len(b)-1].width - b[0].start
		assert.LessOrEqual(t, span, 50, "第 %d 块跨度 %d 超上限", i, span)
	}
}

// 单点位本身超上限:自成一块,交给逐点路径(旧行为)。
func TestChunkPlans_OversizedSinglePoint(t *testing.T) {
	g := []readPlan{
		{start: 0, width: 256}, // STRING 默认宽度,超过小 PDU
		{start: 300, width: 2},
	}
	blocks := chunkPlans(g, 100)
	assert.Equal(t, 2, len(blocks))
	assert.Equal(t, 1, len(blocks[0]))
}

func TestChunkPlans_Empty(t *testing.T) {
	assert.Nil(t, chunkPlans(nil, 222))
	assert.Nil(t, chunkPlans([]readPlan{}, 222))
}

// PDU 载荷换算:未协商时用保守缺省,不能算出 0 或负数。
func TestUsablePayload(t *testing.T) {
	assert.Equal(t, 240-s7ReplyHeader, usablePayload(240))
	assert.Equal(t, 480-s7ReplyHeader, usablePayload(480))
	// 未协商(0 或负)→ 用缺省值
	assert.Equal(t, s7FallbackPDU-s7ReplyHeader, usablePayload(0))
	assert.Equal(t, s7FallbackPDU-s7ReplyHeader, usablePayload(-1))
	// 病态小值不能得出 <1
	assert.Equal(t, 1, usablePayload(10))
	assert.Equal(t, 1, usablePayload(18))
}

func TestItoa(t *testing.T) {
	assert.Equal(t, "0", itoa(0))
	assert.Equal(t, "7", itoa(7))
	assert.Equal(t, "123", itoa(123))
	assert.Equal(t, "-5", itoa(-5))
}
