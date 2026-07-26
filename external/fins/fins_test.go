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
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	finsclient "github.com/rulego/rulego-components-iot/pkg/fins_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// TestFinsNodes 节点类型与默认配置
func TestFinsNodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/finsRead", r.Type())
	assert.NotNil(t, r.New())

	w := &WriteNode{}
	assert.Equal(t, "x/finsWrite", w.Type())
	assert.NotNil(t, w.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:9600", rn.Config.Server)
	assert.Equal(t, 5, rn.Config.Timeout)
}

// TestParseAddr 欧姆龙内存区地址解析(含 CIO 区)。
func TestParseAddr(t *testing.T) {
	cases := []struct {
		addr      string
		area      byte
		address   uint16
		bitOffset byte
		isBit     bool
	}{
		{"CIO100", finsclient.MemoryAreaCIOWord, 100, 0, false},
		{"cio0", finsclient.MemoryAreaCIOWord, 0, 0, false}, // 大小写不敏感
		{"CIO10.7", finsclient.MemoryAreaCIOBit, 10, 7, true},
		{"D100", finsclient.MemoryAreaDMWord, 100, 0, false},
		{"d100", finsclient.MemoryAreaDMWord, 100, 0, false},
		{"DM10", finsclient.MemoryAreaDMWord, 10, 0, false},
		{"D100.5", finsclient.MemoryAreaDMBit, 100, 5, true},
		{"W10", finsclient.MemoryAreaWRWord, 10, 0, false},
		{"WR10", finsclient.MemoryAreaWRWord, 10, 0, false},
		{"W0.15", finsclient.MemoryAreaWRBit, 0, 15, true},
		{"H5", finsclient.MemoryAreaHRWord, 5, 0, false},
		{"HR5", finsclient.MemoryAreaHRWord, 5, 0, false},
		{"A3", finsclient.MemoryAreaARWord, 3, 0, false},
		{"AR3", finsclient.MemoryAreaARWord, 3, 0, false},
	}
	for _, c := range cases {
		area, address, bitOffset, isBit, err := parseAddr(c.addr)
		assert.Nil(t, err, c.addr)
		assert.Equal(t, c.area, area, c.addr)
		assert.Equal(t, c.address, address, c.addr)
		assert.Equal(t, c.bitOffset, bitOffset, c.addr)
		assert.Equal(t, c.isBit, isBit, c.addr)
	}
}

// TestParseAddrError 非法地址。
func TestParseAddrError(t *testing.T) {
	bad := []string{"", "X100", "D", "D1.2.3", "D1.16", "D65536"}
	for _, addr := range bad {
		_, _, _, _, err := parseAddr(addr)
		assert.NotNil(t, err, addr)
	}
}

// TestWordConversion 字序转换往返。
func TestWordConversion(t *testing.T) {
	assert.Equal(t, uint32(0x12345678), wordsToUint32([]uint16{0x1234, 0x5678}))
	assert.Equal(t, []uint16{0x1234, 0x5678}, uint32ToWords(0x12345678))
	assert.Equal(t, uint64(0x1122334455667788), wordsToUint64([]uint16{0x1122, 0x3344, 0x5566, 0x7788}))
	assert.Equal(t, []uint16{0x1122, 0x3344, 0x5566, 0x7788}, uint64ToWords(0x1122334455667788))
}

// TestEncodeDecodeWords 各类型编码解码往返。
func TestEncodeDecodeWords(t *testing.T) {
	roundTrip := func(typ, value string) {
		w, err := encodeWords(typ, value)
		assert.Nil(t, err, typ)
		val, _ := decodeWords(typ, w)
		assert.NotNil(t, val, typ)
	}
	roundTrip("UINT16", "1234")
	roundTrip("INT32", "100000")
	roundTrip("UINT64", "1234567890123")
	roundTrip("FLOAT32", "23.5")
	roundTrip("FLOAT64", "3.141592653589793")

	// 有符号类型负值编码解码
	roundTrip("INT16", "-1")
	roundTrip("INT32", "-100000")
	roundTrip("INT64", "-1234567890123")

	// FLOAT32 编解码精确性
	w, _ := encodeWords("FLOAT32", "23.5")
	val, _ := decodeWords("FLOAT32", w)
	assert.Equal(t, float32(23.5), val)

	// INT16 负值编解码精确性
	w, _ = encodeWords("INT16", "-2")
	val, _ = decodeWords("INT16", w)
	assert.Equal(t, int16(-2), val)

	// 未知类型与 STRING 不支持
	_, err := encodeWords("STRING", "abc")
	assert.NotNil(t, err)
	_, err = wordCount("CUSTOM")
	assert.NotNil(t, err)
}

// TestParseBoolValue 布尔值解析。
func TestParseBoolValue(t *testing.T) {
	for _, s := range []string{"1", "true", "TRUE"} {
		b, err := parseBoolValue(s)
		assert.Nil(t, err, s)
		assert.Equal(t, true, b, s)
	}
	for _, s := range []string{"0", "false"} {
		b, err := parseBoolValue(s)
		assert.Nil(t, err, s)
		assert.Equal(t, false, b, s)
	}
	_, err := parseBoolValue("2")
	assert.NotNil(t, err)
}

// --- in-process FINS PLC 模拟器(字区/位区，标准 W342 区码) ---

// mockPLC 按内存区码维护字/位存储
type mockPLC struct {
	mu    sync.Mutex
	words map[byte][]byte
	bits  map[byte][]byte
}

func newMockPLC() *mockPLC {
	return &mockPLC{
		words: map[byte][]byte{
			finsclient.MemoryAreaDMWord:  make([]byte, 4096),
			finsclient.MemoryAreaCIOWord: make([]byte, 4096),
			finsclient.MemoryAreaWRWord:  make([]byte, 4096),
			finsclient.MemoryAreaHRWord:  make([]byte, 4096),
			finsclient.MemoryAreaARWord:  make([]byte, 4096),
		},
		bits: map[byte][]byte{
			finsclient.MemoryAreaDMBit:  make([]byte, 4096),
			finsclient.MemoryAreaCIOBit: make([]byte, 4096),
			finsclient.MemoryAreaWRBit:  make([]byte, 4096),
			finsclient.MemoryAreaHRBit:  make([]byte, 4096),
			finsclient.MemoryAreaARBit:  make([]byte, 4096),
		},
	}
}

// handle 处理一个 FINS 命令帧，返回完整响应帧
func (m *mockPLC) handle(frame []byte) []byte {
	if len(frame) < 18 {
		return nil
	}
	resp := make([]byte, 14)
	copy(resp[0:10], frame[0:10])
	resp[0] = 0xC0 // 响应帧
	resp[3], resp[6] = frame[6], frame[3]
	resp[4], resp[7] = frame[7], frame[4]
	resp[5], resp[8] = frame[8], frame[5]
	resp[10] = frame[10] // MRC
	resp[11] = frame[11] // SRC
	resp[12] = 0         // MRES
	resp[13] = 0         // SRES

	cmd := binary.BigEndian.Uint16(frame[10:12])
	area := frame[12]
	addr := int(binary.BigEndian.Uint16(frame[13:15]))
	bitOff := int(frame[15])
	count := int(binary.BigEndian.Uint16(frame[16:18]))

	m.mu.Lock()
	defer m.mu.Unlock()
	isBit := m.bits[area] != nil
	store := m.words[area]
	if isBit {
		store = m.bits[area]
	}
	if store == nil {
		resp[12] = 0x22 // 不支持的内存区
		return resp
	}
	switch cmd {
	case 0x0101: // 读
		if isBit {
			start := addr + bitOff
			if start+count > len(store) {
				resp[12] = 0x23
				return resp
			}
			resp = append(resp, store[start:start+count]...)
		} else {
			byteAddr := addr * 2
			if byteAddr+count*2 > len(store) {
				resp[12] = 0x23
				return resp
			}
			resp = append(resp, store[byteAddr:byteAddr+count*2]...)
		}
	case 0x0102: // 写
		data := frame[18:]
		if isBit {
			start := addr + bitOff
			if start+len(data) > len(store) {
				resp[12] = 0x23
				return resp
			}
			copy(store[start:], data)
		} else {
			byteAddr := addr * 2
			if byteAddr+len(data) > len(store) {
				resp[12] = 0x23
				return resp
			}
			copy(store[byteAddr:], data)
		}
	default:
		resp[12] = 0x22
	}
	return resp
}

// startUDPSimulator 启动进程内 FINS/UDP PLC 模拟器，返回地址与清理函数
func startUDPSimulator(t *testing.T) (*mockPLC, string, func()) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free udp port (skip fins test): %v", err)
	}
	plc := newMockPLC()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := plc.handle(buf[:n]); resp != nil {
				_, _ = conn.WriteTo(resp, raddr)
			}
		}
	}()
	return plc, conn.LocalAddr().String(), func() { conn.Close() }
}

// startTCPSimulator 启动进程内 FINS/TCP PLC 模拟器(含节点地址握手)，返回地址与清理函数
func startTCPSimulator(t *testing.T) (*mockPLC, string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free tcp port (skip fins test): %v", err)
	}
	plc := newMockPLC()
	wrap := func(command uint32, payload []byte) []byte {
		frame := make([]byte, 16, 16+len(payload))
		copy(frame[0:4], "FINS")
		binary.BigEndian.PutUint32(frame[4:8], uint32(8+len(payload)))
		binary.BigEndian.PutUint32(frame[8:12], command)
		return append(frame, payload...)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// 握手：服务端节点 21，分配客户端节点 17
				if _, err := c.Write(wrap(0x00000000, []byte{0, 0, 0, 21, 0, 0, 0, 17})); err != nil {
					return
				}
				header := make([]byte, 16)
				for {
					if _, err := io.ReadFull(c, header); err != nil {
						return
					}
					length := int(binary.BigEndian.Uint32(header[4:8]))
					payload := make([]byte, length-8)
					if _, err := io.ReadFull(c, payload); err != nil {
						return
					}
					if binary.BigEndian.Uint32(header[8:12]) != 0x00000002 {
						continue
					}
					if resp := plc.handle(payload); resp != nil {
						if _, err := c.Write(wrap(0x00000002, resp)); err != nil {
							return
						}
					}
				}
			}(conn)
		}
	}()
	return plc, l.Addr().String(), func() { l.Close() }
}

// newTestClient 建立指向模拟器的 FINS client(UDP)。
func newTestClient(t *testing.T, addr string) *finsclient.Client {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	local := finsclient.NewAddress("0.0.0.0", 0, 0, 1, 0)
	plc := finsclient.NewAddress(host, port, 0, 0, 0)
	client, err := finsclient.NewClient(local, plc, finsclient.WithTimeout(3*time.Second))
	assert.Nil(t, err)
	return client
}

// TestFinsDriverE2E driver 端到端：写后读回 + Scale 工程量转换 + CIO 区。
func TestFinsDriverE2E(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	client := newTestClient(t, addr)
	defer client.Close()
	d := newDriver(client)

	werr := d.WritePoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16", Value: "1234"},
		{Name: "i32", Addr: "D200", Type: "INT32", Value: "100000"},
		{Name: "f32", Addr: "D300", Type: "FLOAT32", Value: "23.5"},
		{Name: "f64", Addr: "D400", Type: "FLOAT64", Value: "3.141592653589793"},
		{Name: "u64", Addr: "D500", Type: "UINT64", Value: "1234567890123"},
		{Name: "bit", Addr: "D0.5", Type: "BOOL", Value: "true"},
		{Name: "cio", Addr: "CIO50", Type: "UINT16", Value: "777"},
	})
	assert.Nil(t, werr)

	data, rerr := d.ReadPoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16"},
		{Name: "i32", Addr: "D200", Type: "INT32"},
		{Name: "f32", Addr: "D300", Type: "FLOAT32"},
		{Name: "f64", Addr: "D400", Type: "FLOAT64"},
		{Name: "u64", Addr: "D500", Type: "UINT64"},
		{Name: "bit", Addr: "D0.5", Type: "BOOL"},
		{Name: "cio", Addr: "CIO50", Type: "UINT16"},
		{Name: "scaled", Addr: "D100", Type: "UINT16", Scale: 0.1, Offset: 1},
	})
	assert.Nil(t, rerr)
	assert.Equal(t, 8, len(data))
	assert.Equal(t, uint16(1234), data[0].Value)
	assert.Equal(t, int32(100000), data[1].Value)
	assert.Equal(t, float32(23.5), data[2].Value)
	assert.Equal(t, 3.141592653589793, data[3].Value)
	assert.Equal(t, uint64(1234567890123), data[4].Value)
	assert.Equal(t, true, data[5].Value)
	assert.Equal(t, uint16(777), data[6].Value)
	assert.Equal(t, 1234*0.1+1, data[7].Value) // Scale: 1234*0.1+1=124.4
}

// TestFinsReadNode finsRead 节点端到端：连接模拟器 -> 读 D 区 -> 输出 Data 列表。
func TestFinsReadNode(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()

	// 先写入 D100=4321
	seed := newTestClient(t, addr)
	assert.Nil(t, newDriver(seed).WritePoints([]iot_points.Point{
		{Name: "seed", Addr: "D100", Type: "UINT16", Value: "4321"},
	}))
	seed.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/finsRead", types.Configuration{
		"server":  addr,
		"timeout": 2,
		"points": []map[string]interface{}{
			{"name": "word", "addr": "D100", "type": "UINT16"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		assert.True(t, strings.Contains(msg.GetData(), "word"), "msg.Data should contain word")
		assert.True(t, strings.Contains(msg.GetData(), "4321"), "msg.Data should contain 4321")
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for fins read callback")
	}
}

// TestFinsReadNodeTCP finsRead 节点 FINS/TCP 传输端到端(含握手)。
func TestFinsReadNodeTCP(t *testing.T) {
	_, addr, cleanup := startTCPSimulator(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/finsRead", types.Configuration{
		"server":    addr,
		"transport": "tcp",
		"timeout":   2,
		"points": []map[string]interface{}{
			{"name": "cioword", "addr": "CIO0", "type": "UINT16"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		assert.True(t, strings.Contains(msg.GetData(), "cioword"), "msg.Data should contain cioword")
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for fins tcp read callback")
	}
}

// TestFinsWriteNode finsWrite 节点端到端：msg.Data 点位(优先于配置) -> 写入模拟器 -> 读回验证。
func TestFinsWriteNode(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/finsWrite", types.Configuration{
		"server":  addr,
		"timeout": 2,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	payload := `[{"name":"word","addr":"D100","type":"UINT16","value":"8888"},{"name":"bit","addr":"D0.5","type":"BOOL","value":"true"}]`
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     payload,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for fins write callback")
	}

	// 读回验证
	verify := newTestClient(t, addr)
	defer verify.Close()
	data, rerr := newDriver(verify).ReadPoints([]iot_points.Point{
		{Name: "word", Addr: "D100", Type: "UINT16"},
		{Name: "bit", Addr: "D0.5", Type: "BOOL"},
	})
	assert.Nil(t, rerr)
	assert.Equal(t, 2, len(data))
	assert.Equal(t, uint16(8888), data[0].Value)
	assert.Equal(t, true, data[1].Value)
}
