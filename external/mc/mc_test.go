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
	"encoding/binary"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moge800/gomcprotocol"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// MC 协议软元件代码（与 gomcprotocol 一致）
const (
	devX = 0x9C
	devM = 0x90
	devW = 0xB4
	devR = 0xAF
	devD = 0xA8
)

// TestMcNodes 节点类型与默认配置
func TestMcNodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/mcRead", r.Type())
	assert.NotNil(t, r.New())

	w := &WriteNode{}
	assert.Equal(t, "x/mcWrite", w.Type())
	assert.NotNil(t, w.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:6000", rn.Config.Server)
	assert.Equal(t, 5, rn.Config.Timeout)
}

// TestParseServer host:port 解析与默认端口
func TestParseServer(t *testing.T) {
	host, port, err := parseServer("192.168.1.10:6001")
	assert.Nil(t, err)
	assert.Equal(t, "192.168.1.10", host)
	assert.Equal(t, 6001, port)

	host, port, err = parseServer("192.168.1.10")
	assert.Nil(t, err)
	assert.Equal(t, "192.168.1.10", host)
	assert.Equal(t, defaultPort, port)

	_, _, err = parseServer("")
	assert.NotNil(t, err)
	_, _, err = parseServer("host:abc")
	assert.NotNil(t, err)
}

// TestParseAddr 三菱软元件地址解析
func TestParseAddr(t *testing.T) {
	// 字软元件（十进制编址）
	device, offset, isBit, err := parseAddr("D100")
	assert.Nil(t, err)
	assert.Equal(t, "D", device)
	assert.Equal(t, 100, offset)
	assert.False(t, isBit)

	// R 文件寄存器
	device, offset, _, err = parseAddr("R200")
	assert.Nil(t, err)
	assert.Equal(t, "R", device)
	assert.Equal(t, 200, offset)

	// 位软元件
	device, offset, isBit, err = parseAddr("M0")
	assert.Nil(t, err)
	assert.Equal(t, "M", device)
	assert.Equal(t, 0, offset)
	assert.True(t, isBit)

	// 十六进制编址（X1F=31）
	device, offset, isBit, err = parseAddr("X1F")
	assert.Nil(t, err)
	assert.Equal(t, "X", device)
	assert.Equal(t, 31, offset)
	assert.True(t, isBit)

	// W 链接寄存器（十六进制编址，W10=16）
	device, offset, isBit, err = parseAddr("W10")
	assert.Nil(t, err)
	assert.Equal(t, "W", device)
	assert.Equal(t, 16, offset)
	assert.False(t, isBit)

	// 两字符软元件 ZR（十六进制编址）
	device, offset, _, err = parseAddr("ZR10")
	assert.Nil(t, err)
	assert.Equal(t, "ZR", device)
	assert.Equal(t, 16, offset)

	// 两字符软元件 TN（十进制编址）
	device, offset, isBit, err = parseAddr("TN5")
	assert.Nil(t, err)
	assert.Equal(t, "TN", device)
	assert.Equal(t, 5, offset)
	assert.False(t, isBit)

	// 三字符软元件 STC 优先于 S
	device, offset, isBit, err = parseAddr("STC3")
	assert.Nil(t, err)
	assert.Equal(t, "STC", device)
	assert.Equal(t, 3, offset)
	assert.True(t, isBit)

	// 小写兼容
	device, _, _, err = parseAddr("d50")
	assert.Nil(t, err)
	assert.Equal(t, "D", device)

	// 非法输入
	_, _, _, err = parseAddr("")
	assert.NotNil(t, err)
	_, _, _, err = parseAddr("ZZ1")
	assert.NotNil(t, err)
	_, _, _, err = parseAddr("D")
	assert.NotNil(t, err)
	_, _, _, err = parseAddr("D1.5")
	assert.NotNil(t, err)
}

// TestWordCount 类型 -> 字数映射
func TestWordCount(t *testing.T) {
	n, err := wordCount("INT16")
	assert.Nil(t, err)
	assert.Equal(t, 1, n)
	n, _ = wordCount("")
	assert.Equal(t, 1, n)
	n, _ = wordCount("FLOAT32")
	assert.Equal(t, 2, n)
	n, _ = wordCount("UINT32")
	assert.Equal(t, 2, n)
	n, _ = wordCount("FLOAT64")
	assert.Equal(t, 4, n)
	_, err = wordCount("STRING")
	assert.NotNil(t, err)
}

// TestDecodeEncodeWords 字序列编解码（MELSEC 原生字节序：字内小端、低字在前）
func TestDecodeEncodeWords(t *testing.T) {
	// INT16 负数
	v, err := decodeWords([]uint16{0xFFFF}, "INT16")
	assert.Nil(t, err)
	assert.Equal(t, int16(-1), v)

	// UINT16
	v, _ = decodeWords([]uint16{0xABCD}, "UINT16")
	assert.Equal(t, uint16(0xABCD), v)

	// 空类型按 INT16
	v, _ = decodeWords([]uint16{5}, "")
	assert.Equal(t, int16(5), v)

	// BOOL
	v, _ = decodeWords([]uint16{1}, "BOOL")
	assert.Equal(t, true, v)

	// INT32：低字在前（-123456 = 0xFFFE1DC0 -> 低字 0x1DC0 高字 0xFFFE）
	v, _ = decodeWords([]uint16{0x1DC0, 0xFFFE}, "INT32")
	assert.Equal(t, int32(-123456), v)

	// FLOAT32 23.5
	words, err := encodeValue("23.5", "FLOAT32")
	assert.Nil(t, err)
	v, err = decodeWords(words, "FLOAT32")
	assert.Nil(t, err)
	assert.Equal(t, float32(23.5), v)

	// UINT64
	words, _ = encodeValue("1234567890123", "UINT64")
	v, _ = decodeWords(words, "UINT64")
	assert.Equal(t, uint64(1234567890123), v)

	// FLOAT64
	words, _ = encodeValue("-273.15", "FLOAT64")
	v, _ = decodeWords(words, "FLOAT64")
	assert.Equal(t, -273.15, v)

	// encode INT16 负数
	words, err = encodeValue("-1", "INT16")
	assert.Nil(t, err)
	assert.Equal(t, uint16(0xFFFF), words[0])

	// 非法值
	_, err = encodeValue("abc", "INT16")
	assert.NotNil(t, err)
	_, err = encodeValue("1", "STRING")
	assert.NotNil(t, err)
}

// mockPLC 进程内 MC 协议 3E 帧(二进制)模拟 PLC
type mockPLC struct {
	mu    sync.Mutex
	words map[byte]map[int]uint16
	bits  map[byte]map[int]bool
	ln    net.Listener
}

func startMockPLC(t *testing.T) *mockPLC {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock plc listen: %v", err)
	}
	m := &mockPLC{
		words: map[byte]map[int]uint16{},
		bits:  map[byte]map[int]bool{},
		ln:    ln,
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go m.handle(conn)
		}
	}()
	return m
}

func (m *mockPLC) addr() string { return m.ln.Addr().String() }

func (m *mockPLC) close() { _ = m.ln.Close() }

// handle 逐帧读取请求并应答（3E 帧：9 字节头 + 数据）
func (m *mockPLC) handle(conn net.Conn) {
	defer conn.Close()
	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		body := make([]byte, int(binary.LittleEndian.Uint16(hdr[7:])))
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		if _, err := conn.Write(m.dispatch(body)); err != nil {
			return
		}
	}
}

// dispatch 解析请求体并生成响应。
// 请求体：timer(2) cmd(2) subcmd(2) | addr(3) devcode(1) count(2) [data]
func (m *mockPLC) dispatch(body []byte) []byte {
	endCode := uint16(0)
	var payload []byte
	if len(body) < 12 {
		return m.frame(0x0002, nil)
	}
	cmd := binary.LittleEndian.Uint16(body[2:4])
	subcmd := binary.LittleEndian.Uint16(body[4:6])
	addr := int(body[6]) | int(body[7])<<8 | int(body[8])<<16
	dev := body[9]
	count := int(binary.LittleEndian.Uint16(body[10:12]))
	switch {
	case cmd == 0x0401 && subcmd == 0x0000: // 字单位批量读
		payload = m.readWords(dev, addr, count)
	case cmd == 0x0401 && subcmd == 0x0001: // 位单位批量读
		payload = m.readBits(dev, addr, count)
	case cmd == 0x1401 && subcmd == 0x0000: // 字单位批量写
		m.writeWords(dev, addr, body[12:])
	case cmd == 0x1401 && subcmd == 0x0001: // 位单位批量写
		m.writeBits(dev, addr, body[12:], count)
	default:
		endCode = 0x0002
	}
	return m.frame(endCode, payload)
}

// frame 组装 3E 响应帧：D0 00 头 + 长度 + endcode + payload
func (m *mockPLC) frame(endCode uint16, payload []byte) []byte {
	body := make([]byte, 2+len(payload))
	binary.LittleEndian.PutUint16(body, endCode)
	copy(body[2:], payload)
	frame := make([]byte, 9+len(body))
	copy(frame, []byte{0xD0, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00})
	binary.LittleEndian.PutUint16(frame[7:], uint16(len(body)))
	copy(frame[9:], body)
	return frame
}

func (m *mockPLC) readWords(dev byte, addr, count int) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf := make([]byte, count*2)
	for i := 0; i < count; i++ {
		binary.LittleEndian.PutUint16(buf[i*2:], m.words[dev][addr+i])
	}
	return buf
}

func (m *mockPLC) writeWords(dev byte, addr int, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.words[dev] == nil {
		m.words[dev] = map[int]uint16{}
	}
	for i := 0; i+2 <= len(data); i += 2 {
		m.words[dev][addr+i/2] = binary.LittleEndian.Uint16(data[i:])
	}
}

// readBits 位读取打包：偶数位高半字节、奇数位低半字节（与 gomcprotocol 解码一致）
func (m *mockPLC) readBits(dev byte, addr, count int) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf := make([]byte, (count+1)/2)
	for i := 0; i < count; i++ {
		if m.bits[dev][addr+i] {
			if i%2 == 0 {
				buf[i/2] |= 0x10
			} else {
				buf[i/2] |= 0x01
			}
		}
	}
	return buf
}

func (m *mockPLC) writeBits(dev byte, addr int, data []byte, count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bits[dev] == nil {
		m.bits[dev] = map[int]bool{}
	}
	for i := 0; i < count && i/2 < len(data); i++ {
		b := data[i/2]
		if i%2 == 0 {
			m.bits[dev][addr+i] = (b>>4)&0x01 != 0
		} else {
			m.bits[dev][addr+i] = b&0x01 != 0
		}
	}
}

// 预置/读取存储（测试辅助）
func (m *mockPLC) setWords(dev byte, addr int, vals ...uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.words[dev] == nil {
		m.words[dev] = map[int]uint16{}
	}
	for i, v := range vals {
		m.words[dev][addr+i] = v
	}
}

func (m *mockPLC) getWords(dev byte, addr, count int) []uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	vals := make([]uint16, count)
	for i := 0; i < count; i++ {
		vals[i] = m.words[dev][addr+i]
	}
	return vals
}

func (m *mockPLC) setBit(dev byte, addr int, on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bits[dev] == nil {
		m.bits[dev] = map[int]bool{}
	}
	m.bits[dev][addr] = on
}

func (m *mockPLC) getBit(dev byte, addr int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bits[dev][addr]
}

// TestDriverReadWriteEndToEnd driver 层端到端：写后读回（字/位/多字类型/工程量转换）
func TestDriverReadWriteEndToEnd(t *testing.T) {
	plc := startMockPLC(t)
	defer plc.close()

	host, portStr, _ := net.SplitHostPort(plc.addr())
	port, _ := strconv.Atoi(portStr)
	client, err := gomcprotocol.New3EClient(host, port, gomcprotocol.ModeBinary)
	assert.Nil(t, err)
	assert.Nil(t, client.Connect())
	defer client.Close()
	d := newDriver(client)

	// 写入多类型点位
	err = d.WritePoints([]iot_points.Point{
		{Name: "温度", Addr: "D100", Type: "FLOAT32", Value: "23.5"},
		{Name: "计数", Addr: "D200", Type: "INT32", Value: "-123456"},
		{Name: "标志", Addr: "M5", Type: "BOOL", Value: "true"},
		{Name: "文件", Addr: "R10", Type: "UINT16", Value: "0x1234"},
		{Name: "链接", Addr: "W8", Type: "INT16", Value: "-5"},
	})
	assert.Nil(t, err)

	// 读回校验
	datas, err := d.ReadPoints([]iot_points.Point{
		{Name: "温度", Addr: "D100", Type: "FLOAT32"},
		{Name: "计数", Addr: "D200", Type: "INT32"},
		{Name: "标志", Addr: "M5", Type: "BOOL"},
		{Name: "文件", Addr: "R10", Type: "UINT16"},
		{Name: "链接", Addr: "W8", Type: "INT16"},
	})
	assert.Nil(t, err)
	assert.Equal(t, 5, len(datas))
	assert.Equal(t, float32(23.5), datas[0].Value)
	assert.Equal(t, int32(-123456), datas[1].Value)
	assert.Equal(t, true, datas[2].Value)
	assert.Equal(t, uint16(0x1234), datas[3].Value)
	assert.Equal(t, int16(-5), datas[4].Value)

	// 工程量转换：D300 原始 100，scale=0.1 offset=2 -> 12
	plc.setWords(devD, 300, 100)
	datas, err = d.ReadPoints([]iot_points.Point{
		{Name: "换算", Addr: "D300", Type: "UINT16", Scale: 0.1, Offset: 2},
	})
	assert.Nil(t, err)
	assert.Equal(t, 100*0.1+2, datas[0].Value)

	// 单点失败标记 Error，成功点正常返回
	datas, err = d.ReadPoints([]iot_points.Point{
		{Name: "非法", Addr: "ZZ1", Type: "UINT16"},
		{Name: "正常", Addr: "D300", Type: "UINT16"},
	})
	assert.Nil(t, err)
	assert.True(t, datas[0].Error != "")
	assert.Equal(t, uint16(100), datas[1].Value)

	// 全部失败返回 error
	_, err = d.ReadPoints([]iot_points.Point{{Name: "非法", Addr: "ZZ1"}})
	assert.NotNil(t, err)
}

// TestMcReadNodeEndToEnd mcRead 节点端到端：连接 mock PLC -> 读取点位 -> 输出 Data 列表。
// msg.Data 带点位时优先于配置 points（双入口）。
func TestMcReadNodeEndToEnd(t *testing.T) {
	plc := startMockPLC(t)
	defer plc.close()
	// 预置 D100=23.5(FLOAT32)、D200=777
	plc.setWords(devD, 100, split32(math.Float32bits(23.5))...)
	plc.setWords(devD, 200, 777)
	plc.setBit(devM, 0, true)

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/mcRead", types.Configuration{
		"server":  plc.addr(),
		"timeout": 5,
		"points": []map[string]interface{}{
			{"name": "温度", "addr": "D100", "type": "FLOAT32"},
			{"name": "运行", "addr": "M0", "type": "BOOL"},
		},
	}, registry)
	assert.Nil(t, err)

	// 配置 points 入口
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: `{}`}},
		func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.True(t, strings.Contains(msg.GetData(), "温度"))
			assert.True(t, strings.Contains(msg.GetData(), "23.5"))
			assert.True(t, strings.Contains(msg.GetData(), "运行"))
			done <- struct{}{}
		})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for mc read callback")
	}

	// msg.Data 点位入口优先（读 D200 而非配置的温度/运行）
	done2 := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST",
		Data: `[{"name":"计数","addr":"D200","type":"UINT16"}]`}},
		func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.True(t, strings.Contains(msg.GetData(), "计数"))
			assert.True(t, strings.Contains(msg.GetData(), "777"))
			done2 <- struct{}{}
		})
	select {
	case <-done2:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for mc read (msg.Data points) callback")
	}
}

// TestMcWriteNodeEndToEnd mcWrite 节点端到端：从 msg.Data 读点位 -> 写入 mock PLC -> 校验存储。
func TestMcWriteNodeEndToEnd(t *testing.T) {
	plc := startMockPLC(t)
	defer plc.close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/mcWrite", types.Configuration{
		"server":  plc.addr(),
		"timeout": 5,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	writePayload := `[{"name":"计数","addr":"D10","type":"UINT16","value":"4321"},{"name":"运行","addr":"M0","type":"BOOL","value":"true"},{"name":"温度","addr":"D20","type":"FLOAT32","value":"65.5"}]`
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: writePayload}},
		func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			done <- struct{}{}
		})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for mc write callback")
	}

	assert.Equal(t, uint16(4321), plc.getWords(devD, 10, 1)[0])
	assert.Equal(t, true, plc.getBit(devM, 0))
	got := plc.getWords(devD, 20, 2)
	assert.Equal(t, float32(65.5), math.Float32frombits(uint32(got[1])<<16|uint32(got[0])))
}

// TestMcReadFailureNoPLC 无 PLC 时连接失败，节点走 Failure 链
func TestMcReadFailureNoPLC(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/mcRead", types.Configuration{
		"server":  "127.0.0.1:19999",
		"timeout": 1,
		"points": []map[string]interface{}{
			{"name": "温度", "addr": "D100", "type": "FLOAT32"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: `{}`}},
		func(msg types.RuleMsg, relationType string, err error) {
			assert.Equal(t, types.Failure, relationType)
			if err == nil {
				t.Fatal("should have connection error for unreachable PLC")
			}
			done <- struct{}{}
		})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for mc read failure callback")
	}
}
