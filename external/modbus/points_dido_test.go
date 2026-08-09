package modbus

import (
	"testing"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/simonvetter/modbus"
	"github.com/stretchr/testify/assert"
)

// DI/DO(线圈 + 离散输入)与寄存器混在同一产品里时的行为。
//
// 背景:开关量模块常以 Modbus 从站暴露,一个产品里会同时出现
// 线圈(1~9999,可读写)、离散输入(10001~19999,只读)与保持寄存器(40001+)。
// 分组键是 (regType, kind),所以三类地址不会混进同一次请求 —— 本测试锁定这个语义,
// 否则 chunkPlans 会用"碰巧排第一"那个 kind 的上限(位空间 2000 vs 寄存器 125)。

// mixedDIDOPoints 造一组 DI + DO + 保持寄存器混合点位。
func mixedDIDOPoints() []iot_points.Point {
	return []iot_points.Point{
		{Name: "do1", Addr: "1", Type: iot_points.TypeBool},
		{Name: "do2", Addr: "2", Type: iot_points.TypeBool},
		{Name: "di1", Addr: "10001", Type: iot_points.TypeBool},
		{Name: "di2", Addr: "10002", Type: iot_points.TypeBool},
		{Name: "temp", Addr: "40001", Type: iot_points.TypeFloat32},
	}
}

func TestReadPoints_MixedDIDOAndRegisters(t *testing.T) {
	h := newCountingHandler()
	// 注意顺序:fillDeterministic 会覆盖 coils/di,显式值必须放它之后。
	fillDeterministic(h)
	h.coils[0] = true  // Modicon 1 → protocol 0
	h.coils[1] = false // Modicon 2
	h.di[0] = false    // Modicon 10001 → protocol 0
	h.di[1] = true     // Modicon 10002
	d := newCountingDriver(t, h, "15731", modbus.HIGH_WORD_FIRST)

	data, err := d.ReadPoints(mixedDIDOPoints())
	assert.Nil(t, err)
	assert.Equal(t, 5, len(data))

	byName := map[string]iot_points.Data{}
	for _, x := range data {
		byName[x.Name] = x
	}
	// 线圈与离散输入都应按 bool 解出,且值与 mock 一致。
	assert.Equal(t, "", byName["do1"].Error)
	assert.Equal(t, true, toBoolValue(byName["do1"]))
	assert.Equal(t, false, toBoolValue(byName["do2"]))
	assert.Equal(t, false, toBoolValue(byName["di1"]))
	assert.Equal(t, true, toBoolValue(byName["di2"]))
	// 寄存器点不受影响。
	assert.Equal(t, "", byName["temp"].Error)
}

// 三类地址各自合并成一次请求:5 个点位应只发 3 次(线圈1次+离散1次+寄存器1次)。
// 若分组没按 kind 隔离,请求数或解出的值会不对。
func TestReadPoints_MixedGroupsMergeSeparately(t *testing.T) {
	h := newCountingHandler()
	fillDeterministic(h)
	d := newCountingDriver(t, h, "15732", modbus.HIGH_WORD_FIRST)

	h.resetReqs()
	data, err := d.ReadPoints(mixedDIDOPoints())
	assert.Nil(t, err)
	assert.Equal(t, 5, len(data))
	assert.Equal(t, 3, h.reqs(), "线圈/离散输入/寄存器各一次请求,不应混组也不应逐点读")
}

// 与逐点读等价:混合点位的批读结果必须和一个个读完全一致。
func TestReadPoints_MixedEquivalentToPerPoint(t *testing.T) {
	h := newCountingHandler()
	fillDeterministic(h)
	h.coils[0], h.coils[1] = true, true
	h.di[0], h.di[1] = true, false
	d := newCountingDriver(t, h, "15733", modbus.HIGH_WORD_FIRST)

	pts := mixedDIDOPoints()
	batch, err := d.ReadPoints(pts)
	assert.Nil(t, err)
	single := readPerPoint(d, pts)

	assert.Equal(t, len(single), len(batch))
	for i := range batch {
		assert.Equal(t, single[i].Name, batch[i].Name)
		assert.Equal(t, single[i].Error, batch[i].Error)
		assert.Equal(t, single[i].Value, batch[i].Value, "点位 %s 批读与逐点读不一致", batch[i].Name)
	}
}

// 写线圈:DO 下发必须真正落到 coil 空间。
func TestWritePoints_Coil(t *testing.T) {
	h := newCountingHandler()
	d := newCountingDriver(t, h, "15734", modbus.HIGH_WORD_FIRST)

	err := d.WritePoints([]iot_points.Point{
		{Name: "do1", Addr: "1", Type: iot_points.TypeBool, Value: "true"},
	})
	assert.Nil(t, err)
	assert.Equal(t, true, h.coils[0], "Modicon 1 应写到 protocol 地址 0")

	// 再写回 false,确认不是一次性置位。
	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "do1", Addr: "1", Type: iot_points.TypeBool, Value: "false"},
	}))
	assert.Equal(t, false, h.coils[0])
}

// 离散输入是只读区:写它应报错而不是静默成功(否则用户以为下发了)。
func TestWritePoints_DiscreteInputRejected(t *testing.T) {
	h := newCountingHandler()
	d := newCountingDriver(t, h, "15735", modbus.HIGH_WORD_FIRST)

	err := d.WritePoints([]iot_points.Point{
		{Name: "di1", Addr: "10001", Type: iot_points.TypeBool, Value: "true"},
	})
	assert.NotNil(t, err, "写离散输入(只读区)必须报错")
}

// toBoolValue 从 Data 取 bool 值(Value 是 any)。
func toBoolValue(d iot_points.Data) bool {
	if b, ok := d.Value.(bool); ok {
		return b
	}
	return false
}
