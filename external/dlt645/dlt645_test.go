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
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// assertFloat 断言 got 为 float64 且与 want 近似相等。
func assertFloat(t *testing.T, want float64, got interface{}) {
	t.Helper()
	f, ok := got.(float64)
	if !ok {
		t.Fatalf("value %v (%T) is not float64", got, got)
	}
	if math.Abs(f-want) > 1e-9 {
		t.Fatalf("want %v, got %v", want, f)
	}
}

// --- codec 纯函数测试 ---

// TestChecksum 算术和低 8 位（手工计算值）。
func TestChecksum(t *testing.T) {
	// 68 01 00 00 00 00 00 68 11 04 33 33 34 33 → 0x1B3 → 0xB3
	frame := []byte{0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x11, 0x04, 0x33, 0x33, 0x34, 0x33}
	assert.Equal(t, byte(0xB3), Checksum(frame))
	assert.Equal(t, byte(0), Checksum(nil))
}

// TestBCD 编解码往返与补零。
func TestBCD(t *testing.T) {
	// 高位数字在高字节
	assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78}, EncodeBCD(12345678, 4))
	assert.Equal(t, []byte{0x00, 0x00, 0x22, 0x05}, EncodeBCD(2205, 4)) // 高位补零
	assert.Equal(t, []byte{0x00}, EncodeBCD(0, 1))

	assert.Equal(t, uint64(12345678), DecodeBCD([]byte{0x12, 0x34, 0x56, 0x78}))
	assert.Equal(t, uint64(2205), DecodeBCD([]byte{0x00, 0x00, 0x22, 0x05}))
	assert.Equal(t, uint64(0), DecodeBCD([]byte{0x00, 0x00}))
	assert.Equal(t, uint64(99), DecodeBCD([]byte{0x99}))

	// 往返
	for _, v := range []uint64{0, 1, 99, 100, 9999, 12345678, 999999999999} {
		assert.Equal(t, v, DecodeBCD(EncodeBCD(v, 6)))
	}
}

// TestParseAddr 表地址解析（12 位 BCD，低字节在前）。
func TestParseAddr(t *testing.T) {
	a, err := ParseAddr("000000000001")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, a)

	a, err = ParseAddr("123456789012")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x12, 0x90, 0x78, 0x56, 0x34, 0x12}, a)

	// 不足 12 位左补零
	a, err = ParseAddr("1234")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x34, 0x12, 0x00, 0x00, 0x00, 0x00}, a)

	// 格式化往返
	assert.Equal(t, "123456789012", FormatAddr([]byte{0x12, 0x90, 0x78, 0x56, 0x34, 0x12}))

	// 非法
	for _, bad := range []string{"", "0000000000001", "12345678901A", "abcdef"} {
		_, err := ParseAddr(bad)
		assert.NotNil(t, err, "addr %q should be invalid", bad)
	}
}

// TestParseDI 数据标识解析（标准书写序 → 线序低字节在前）。
func TestParseDI(t *testing.T) {
	// 02-01-01-00 = DI3 DI2 DI1 DI0 → 线序 DI0..DI3
	di, err := ParseDI("02-01-01-00")
	assert.Nil(t, err)
	assert.Equal(t, [4]byte{0x00, 0x01, 0x01, 0x02}, di)

	di, err = ParseDI("00-01-00-00")
	assert.Nil(t, err)
	assert.Equal(t, [4]byte{0x00, 0x00, 0x01, 0x00}, di)

	// 连写格式等价
	di2, err := ParseDI("02010100")
	assert.Nil(t, err)
	assert.Equal(t, [4]byte{0x00, 0x01, 0x01, 0x02}, di2)

	// 格式化往返
	assert.Equal(t, "00-01-00-00", FormatDI(di))
	assert.Equal(t, "02-01-01-00", FormatDI(di2))

	// 非法
	for _, bad := range []string{"", "02-01-01", "02-01-01-00-00", "zz-01-01-00", "010203"} {
		_, err := ParseDI(bad)
		assert.NotNil(t, err, "DI %q should be invalid", bad)
	}
}

// TestBuildReadFrame 读请求帧逐字节断言（含 0x33、CS、帧尾）。
func TestBuildReadFrame(t *testing.T) {
	// 地址 000000000001，DI 00-01-00-00（正向有功总电能）
	di, _ := ParseDI("00-01-00-00")
	frame, err := BuildReadFrame("000000000001", di[:])
	assert.Nil(t, err)
	assert.Equal(t, []byte{
		0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, // 帧头 + 地址 + 0x68
		0x11, 0x04, // 控制码读数据 + 长度 4
		0x33, 0x33, 0x34, 0x33, // DI 加 0x33
		0xB3, // CS（手工计算）
		0x16, // 帧尾
	}, frame)

	// 地址 123456789012，DI 02-01-01-00（A 相电压）
	di, _ = ParseDI("02-01-01-00")
	frame, err = BuildReadFrame("123456789012", di[:])
	assert.Nil(t, err)
	assert.Equal(t, []byte{
		0x68, 0x12, 0x90, 0x78, 0x56, 0x34, 0x12, 0x68,
		0x11, 0x04,
		0x33, 0x34, 0x34, 0x35,
		0x6B, // CS（手工计算）
		0x16,
	}, frame)

	// 非法 DI 长度
	_, err = BuildReadFrame("000000000001", []byte{0x00, 0x01})
	assert.NotNil(t, err)
	// 非法地址
	_, err = BuildReadFrame("xyz", di[:])
	assert.NotNil(t, err)
}

// TestBuildWriteFrame 写请求帧：数据域 = DI + 数据，均加 0x33。
func TestBuildWriteFrame(t *testing.T) {
	di, _ := ParseDI("00-01-00-00")
	// 写数据 [0x00,0x01]（100.00 kWh 的 BCD 线序）
	frame, err := BuildWriteFrame("000000000001", di[:], []byte{0x00, 0x01})
	assert.Nil(t, err)

	ctrl, _, payload, perr := parseFrame(frame)
	assert.Nil(t, perr)
	assert.Equal(t, byte(ctrlWrite), ctrl)
	// payload = DI + 数据（已减 0x33 还原）
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}, payload)
}

// buildTestResponse 构造应答帧（测试辅助）。
func buildTestResponse(addr string, ctrl byte, payload []byte) []byte {
	addrBytes, _ := ParseAddr(addr)
	return buildFrame(addrBytes, ctrl, payload)
}

// TestParseResponse 正常/异常/损坏帧解析。
func TestParseResponse(t *testing.T) {
	// 正常应答：DI(00-01-00-00) + 电能数据 123456.78 kWh
	resp := buildTestResponse("000000000001", ctrlRead|respMask,
		[]byte{0x00, 0x00, 0x01, 0x00, 0x78, 0x56, 0x34, 0x12})
	// 逐字节断言（0x33 变换 + CS 手工值）
	assert.Equal(t, []byte{
		0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68,
		0x91, 0x08,
		0x33, 0x33, 0x34, 0x33, 0xAB, 0x89, 0x67, 0x45,
		0x17, // CS（手工计算）
		0x16,
	}, resp)
	di, data, err := ParseResponse(resp)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x00}, di)
	assert.Equal(t, []byte{0x78, 0x56, 0x34, 0x12}, data)

	// 异常应答：ERR=0x03 无数据（控制码 0x11|0xC0=0xD1）
	resp = buildTestResponse("000000000001", ctrlRead|respMask|errMask, []byte{0x03})
	assert.Equal(t, []byte{
		0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68,
		0xD1, 0x01, 0x36,
		0xD9, // CS（手工计算）
		0x16,
	}, resp)
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "no data"), err)

	// 校验和错误
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00, 0x00})
	resp[len(resp)-2]++ // 篡改 CS
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "checksum"), err)

	// 篡改数据域导致校验失败
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00, 0x00})
	resp[10]++
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)

	// 帧过短
	_, _, err = ParseResponse([]byte{0x68, 0x00})
	assert.NotNil(t, err)

	// 长度字段不匹配
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00})
	_, _, err = ParseResponse(resp[:len(resp)-1])
	assert.NotNil(t, err)

	// 帧尾错误
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00})
	resp[len(resp)-1] = 0x00
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)

	// 非从站应答帧（主站请求帧）
	diBytes, _ := ParseDI("00-01-00-00")
	req, _ := BuildReadFrame("000000000001", diBytes[:])
	_, _, err = ParseResponse(req)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "not a slave response"), err)
}

// --- 值解码测试 ---

// TestDecodeValue 按 DI 标准/Type 解码各类数据。
func TestDecodeValue(t *testing.T) {
	cases := []struct {
		name string
		di   string
		raw  []byte
		pt   iot_points.Point
		want interface{}
	}{
		// 正向有功总电能：BCD 4 字节 2 位小数，123456.78 kWh
		{"电能", "00-01-00-00", []byte{0x78, 0x56, 0x34, 0x12}, iot_points.Point{}, 123456.78},
		// A 相电压：BCD 3 字节 1 位小数，220.5 V
		{"电压", "02-01-01-00", []byte{0x05, 0x22, 0x00}, iot_points.Point{}, 220.5},
		// A 相电流：BCD 3 字节 3 位小数带符号，1.500 A
		{"电流正", "02-02-01-00", []byte{0x00, 0x15, 0x00}, iot_points.Point{}, 1.5},
		// A 相电流负值：最高字节 bit7 置位，-1.500 A
		{"电流负", "02-02-01-00", []byte{0x00, 0x15, 0x80}, iot_points.Point{}, -1.5},
		// 瞬时总有功功率负值：-5.1234 kW
		{"功率负", "02-03-00-00", []byte{0x34, 0x12, 0x85}, iot_points.Point{}, -5.1234},
		// 未知 DI：无符号 BCD 整数
		{"未知DI", "05-06-00-00", []byte{0x21, 0x43}, iot_points.Point{}, uint64(4321)},
		// Type BCD + Scale：原始 BCD 整数 × scale
		{"BCD缩放", "05-06-00-00", []byte{0x78, 0x56, 0x34, 0x12}, iot_points.Point{Type: "BCD", Scale: 0.01}, 123456.78},
		// 电能 + Scale/Offset 工程转换：100.00 kWh → 201.0
		{"缩放偏移", "00-01-00-00", []byte{0x00, 0x00, 0x01, 0x00}, iot_points.Point{Scale: 2, Offset: 1}, 201.0},
		// 二进制小端 UINT16
		{"UINT16", "05-06-00-00", []byte{0x39, 0x05}, iot_points.Point{Type: iot_points.TypeUint16}, 1337.0},
		// 二进制小端 INT16 负值
		{"INT16负", "05-06-00-00", []byte{0xFF, 0xFF}, iot_points.Point{Type: iot_points.TypeInt16}, -1.0},
		// 二进制小端 INT32 最小值
		{"INT32最小", "05-06-00-00", []byte{0x00, 0x00, 0x00, 0x80}, iot_points.Point{Type: iot_points.TypeInt32}, -2147483648.0},
		// 二进制小端 INT64 负值
		{"INT64负", "05-06-00-00", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, iot_points.Point{Type: iot_points.TypeInt64}, -1.0},
		// 二进制小端 UINT32
		{"UINT32", "05-06-00-00", []byte{0x40, 0xE2, 0x01, 0x00}, iot_points.Point{Type: iot_points.TypeUint32}, 123456.0},
		// BOOL
		{"BOOL真", "05-06-00-00", []byte{0x01}, iot_points.Point{Type: iot_points.TypeBool}, true},
		{"BOOL假", "05-06-00-00", []byte{0x00}, iot_points.Point{Type: iot_points.TypeBool}, false},
		// STRING
		{"字符串", "05-06-00-00", []byte("AB"), iot_points.Point{Type: iot_points.TypeString}, "AB"},
	}
	for _, c := range cases {
		di, err := ParseDI(c.di)
		assert.Nil(t, err, c.name)
		got, err := decodeValue(di, c.raw, c.pt)
		assert.Nil(t, err, c.name)
		if wantF, ok := c.want.(float64); ok {
			assertFloat(t, wantF, got)
		} else {
			assert.Equal(t, c.want, got, c.name)
		}
	}

	// 不支持的类型
	di, _ := ParseDI("00-01-00-00")
	_, err := decodeValue(di, []byte{0x00}, iot_points.Point{Type: "FLOAT32"})
	assert.NotNil(t, err)
	// 二进制数据过短
	_, err = decodeValue(di, []byte{0x01}, iot_points.Point{Type: iot_points.TypeUint32})
	assert.NotNil(t, err)
}

// TestEncodeWriteValue 写值 BCD 编码（已知 DI 小数位 + Type 字节数 + 符号）。
func TestEncodeWriteValue(t *testing.T) {
	// 功率 DI 4 位小数 + UINT32 → 4 字节线序 BCD：1.2345 → {0x45,0x23,0x01,0x00}
	b, err := encodeWriteValue(iot_points.Point{Addr: "02-03-00-00", Type: iot_points.TypeUint32, Value: "1.2345"})
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x45, 0x23, 0x01, 0x00}, b)

	// 电能 DI 2 位小数 + 无 Type → 自然 3 字节：100.00 → BCD 10000(5位) → {0x00,0x00,0x01}
	b, err = encodeWriteValue(iot_points.Point{Addr: "00-01-00-00", Value: "100.00"})
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x01}, b)

	// 负功率：最高字节点亮符号位 -1.500 → 1500 → {0x00,0x15} → {0x00,0x95}
	b, err = encodeWriteValue(iot_points.Point{Addr: "02-02-01-00", Value: "-1.5"})
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x00, 0x95}, b)

	// 非法值
	_, err = encodeWriteValue(iot_points.Point{Addr: "00-01-00-00", Value: "abc"})
	assert.NotNil(t, err)
}

// --- mock 表 + 端到端测试 ---

// mockMeter 模拟 DLT645 表：收读帧查预置数据返回应答帧，收写帧存储并应答。
type mockMeter struct {
	t    *testing.T
	ln   net.Listener
	addr string
	mu   sync.Mutex
	data map[[diLen]byte][]byte // DI（线序）→ 应答数据（原始字节，未加 0x33）
}

func newMockMeter(t *testing.T, addr string) *mockMeter {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	m := &mockMeter{t: t, ln: ln, addr: addr, data: map[[diLen]byte][]byte{}}
	go m.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return m
}

func (m *mockMeter) port() int { return m.ln.Addr().(*net.TCPAddr).Port }

// set 预置 DI 的应答数据（线序原始字节）。
func (m *mockMeter) set(di string, raw []byte) {
	d, err := ParseDI(di)
	assert.Nil(m.t, err)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[d] = raw
}

func (m *mockMeter) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handle(conn)
	}
}

func (m *mockMeter) handle(conn net.Conn) {
	defer conn.Close()
	for {
		frame, err := readFrame(conn)
		if err != nil {
			return
		}
		ctrl, _, payload, err := parseFrame(frame)
		if err != nil || len(payload) < diLen {
			continue
		}
		var di [diLen]byte
		copy(di[:], payload[:diLen])
		switch ctrl {
		case ctrlRead:
			m.mu.Lock()
			raw, ok := m.data[di]
			m.mu.Unlock()
			if ok {
				m.reply(conn, ctrlRead|respMask, append(di[:], raw...))
			} else {
				m.reply(conn, ctrlRead|respMask|errMask, []byte{0x03}) // 无数据
			}
		case ctrlWrite:
			m.mu.Lock()
			m.data[di] = append([]byte(nil), payload[diLen:]...)
			m.mu.Unlock()
			m.reply(conn, ctrlWrite|respMask, di[:]) // 写应答数据域为 DI
		}
	}
}

// reply 构造并发送应答帧（payload 为未加 0x33 的数据）。
func (m *mockMeter) reply(conn net.Conn, ctrl byte, payload []byte) {
	addrBytes, err := ParseAddr(m.addr)
	if err != nil {
		return
	}
	_, _ = conn.Write(buildFrame(addrBytes, ctrl, payload))
}

// newTestDriver 连接 mock 表并返回 driver（测试结束自动清理）。
func newTestDriver(t *testing.T, m *mockMeter) *driver {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", m.port()))
	assert.Nil(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return newDriver(conn, m.addr, 2*time.Second)
}

// TestDriver_ReadPoints 端到端：预置 4 类数据项，读出值按 DI 标准解码。
func TestDriver_ReadPoints(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	m.set("00-01-00-00", []byte{0x78, 0x56, 0x34, 0x12}) // 123456.78 kWh
	m.set("02-01-01-00", []byte{0x05, 0x22, 0x00})       // 220.5 V
	m.set("02-02-01-00", []byte{0x00, 0x15, 0x80})       // -1.500 A
	m.set("02-03-00-00", []byte{0x34, 0x12, 0x05})       // 5.1234 kW

	d := newTestDriver(t, m)
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "正向有功总电能", Addr: "00-01-00-00"},
		{Name: "A相电压", Addr: "02-01-01-00"},
		{Name: "A相电流", Addr: "02-02-01-00"},
		{Name: "瞬时总有功功率", Addr: "02-03-00-00"},
	})
	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, "正向有功总电能", data[0].Name)
	assertFloat(t, 123456.78, data[0].Value)
	assertFloat(t, 220.5, data[1].Value)
	assertFloat(t, -1.5, data[2].Value)
	assertFloat(t, 5.1234, data[3].Value)
	assert.True(t, data[0].Timestamp > 0)
}

// TestDriver_ReadNoData 表无此数据项 → 异常应答 ERR=0x03。
func TestDriver_ReadNoData(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	d := newTestDriver(t, m)
	_, err := d.ReadPoints([]iot_points.Point{{Name: "x", Addr: "00-01-00-00"}})
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "no data"), err)
}

// TestDriver_ReadInvalidAddr DI 非法 → 解析错误。
func TestDriver_ReadInvalidAddr(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	d := newTestDriver(t, m)
	_, err := d.ReadPoints([]iot_points.Point{{Name: "x", Addr: "bad-di"}})
	assert.NotNil(t, err)
}

// TestDriver_Scale 端到端工程量转换。
func TestDriver_Scale(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	m.set("05-06-00-00", []byte{0x00, 0x01}) // 原始 BCD 100（线序低字节在前）

	d := newTestDriver(t, m)
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "raw", Addr: "05-06-00-00", Type: "BCD", Scale: 0.1, Offset: 5},
	})
	assert.Nil(t, err)
	assertFloat(t, 15.0, data[0].Value) // 100*0.1+5
}

// TestDriver_WriteThenRead 端到端：写入后由 mock 存储，再读出验证。
func TestDriver_WriteThenRead(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	d := newTestDriver(t, m)

	// 写功率 1.2345kW（UINT32，4 位小数）
	err := d.WritePoints([]iot_points.Point{
		{Name: "功率", Addr: "02-03-00-00", Type: iot_points.TypeUint32, Value: "1.2345"},
	})
	assert.Nil(t, err)
	// 读回
	data, err := d.ReadPoints([]iot_points.Point{{Name: "功率", Addr: "02-03-00-00"}})
	assert.Nil(t, err)
	assertFloat(t, 1.2345, data[0].Value)

	// 写电能 100.00 kWh（无 Type，2 位小数自然长度）
	err = d.WritePoints([]iot_points.Point{
		{Name: "电能", Addr: "00-01-00-00", Value: "100.00"},
	})
	assert.Nil(t, err)
	data, err = d.ReadPoints([]iot_points.Point{{Name: "电能", Addr: "00-01-00-00"}})
	assert.Nil(t, err)
	assertFloat(t, 100.0, data[0].Value)
}

// --- 节点级测试 ---

// TestReadNodeNodes 节点类型与默认配置
func TestReadNodeNodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/dlt645Read", r.Type())
	assert.NotNil(t, r.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:8899", rn.Config.Server)
	assert.Equal(t, "000000000001", rn.Config.Addr)
	assert.Equal(t, 5, rn.Config.Timeout)
	assert.Equal(t, 1, len(rn.Config.Points))
}

// TestReadNode_E2E 节点级端到端：配置点位，Success 链输出 Data 列表。
func TestReadNode_E2E(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	m.set("00-01-00-00", []byte{0x78, 0x56, 0x34, 0x12}) // 123456.78 kWh
	m.set("02-01-01-00", []byte{0x05, 0x22, 0x00})       // 220.5 V

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/dlt645Read", types.Configuration{
		"server":  fmt.Sprintf("tcp://127.0.0.1:%d", m.port()),
		"addr":    "000000000001",
		"timeout": 2,
		"points": []map[string]interface{}{
			{"name": "正向有功总电能", "addr": "00-01-00-00"},
			{"name": "A相电压", "addr": "02-01-01-00"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan string, 1)
	var got string
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: `{}`}},
		func(msg types.RuleMsg, relationType string, err error) {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			got = msg.GetData()
			done <- relationType
		})

	select {
	case rt := <-done:
		assert.Equal(t, types.Success, rt)
		var datas []iot_points.Data
		assert.Nil(t, json.Unmarshal([]byte(got), &datas))
		assert.Equal(t, 2, len(datas))
		assert.Equal(t, "正向有功总电能", datas[0].Name)
		assertFloat(t, 123456.78, datas[0].Value)
		assertFloat(t, 220.5, datas[1].Value)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for dlt645 read callback")
	}
}

// TestReadNode_MsgDataPoints 双入口：msg.Data 点位优先于配置，支持 ${metadata.xx} 模板。
func TestReadNode_MsgDataPoints(t *testing.T) {
	m := newMockMeter(t, "000000000002")
	m.set("02-03-00-00", []byte{0x34, 0x12, 0x85}) // -5.1234 kW

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/dlt645Read", types.Configuration{
		"server":  fmt.Sprintf("tcp://127.0.0.1:%d", m.port()),
		"addr":    "000000000002",
		"timeout": 2,
		// 配置点位会被 msg.Data 覆盖
		"points": []map[string]interface{}{
			{"name": "不会读到", "addr": "00-01-00-00"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan string, 1)
	var got string
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		MetaData: types.BuildMetadata(map[string]string{"di": "02-03-00-00"}),
		Data:     `[{"name":"瞬时总有功功率","addr":"${metadata.di}"}]`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		got = msg.GetData()
		done <- relationType
	})

	select {
	case rt := <-done:
		assert.Equal(t, types.Success, rt)
		var datas []iot_points.Data
		assert.Nil(t, json.Unmarshal([]byte(got), &datas))
		assert.Equal(t, 1, len(datas))
		assert.Equal(t, "瞬时总有功功率", datas[0].Name)
		assertFloat(t, -5.1234, datas[0].Value)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for dlt645 read callback")
	}
}

// TestReadNode_NoServer 无表连接失败，节点走 Failure 链。
func TestReadNode_NoServer(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/dlt645Read", types.Configuration{
		"server":  "tcp://127.0.0.1:19998",
		"addr":    "000000000001",
		"timeout": 1,
		"points": []map[string]interface{}{
			{"name": "电能", "addr": "00-01-00-00"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: `{}`}},
		func(msg types.RuleMsg, relationType string, err error) {
			assert.Equal(t, types.Failure, relationType)
			assert.NotNil(t, err)
			done <- struct{}{}
		})

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for dlt645 failure callback")
	}
}
