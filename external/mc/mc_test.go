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

// MC protocol device codes (consistent with gomcprotocol)
const (
	devX = 0x9C
	devM = 0x90
	devW = 0xB4
	devR = 0xAF
	devD = 0xA8
)

// TestMcNodes node types and default configuration
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

// TestParseAddr Mitsubishi device address parsing
func TestParseAddr(t *testing.T) {
	// Word devices (decimal addressing)
	device, offset, isBit, err := parseAddr("D100")
	assert.Nil(t, err)
	assert.Equal(t, "D", device)
	assert.Equal(t, 100, offset)
	assert.False(t, isBit)

	// R file registers
	device, offset, _, err = parseAddr("R200")
	assert.Nil(t, err)
	assert.Equal(t, "R", device)
	assert.Equal(t, 200, offset)

	// Bit devices
	device, offset, isBit, err = parseAddr("M0")
	assert.Nil(t, err)
	assert.Equal(t, "M", device)
	assert.Equal(t, 0, offset)
	assert.True(t, isBit)

	// Hexadecimal addressing (X1F=31)
	device, offset, isBit, err = parseAddr("X1F")
	assert.Nil(t, err)
	assert.Equal(t, "X", device)
	assert.Equal(t, 31, offset)
	assert.True(t, isBit)

	// W link registers (hexadecimal addressing, W10=16)
	device, offset, isBit, err = parseAddr("W10")
	assert.Nil(t, err)
	assert.Equal(t, "W", device)
	assert.Equal(t, 16, offset)
	assert.False(t, isBit)

	// Two-character device ZR (hexadecimal addressing)
	device, offset, _, err = parseAddr("ZR10")
	assert.Nil(t, err)
	assert.Equal(t, "ZR", device)
	assert.Equal(t, 16, offset)

	// Two-character device TN (decimal addressing)
	device, offset, isBit, err = parseAddr("TN5")
	assert.Nil(t, err)
	assert.Equal(t, "TN", device)
	assert.Equal(t, 5, offset)
	assert.False(t, isBit)

	// Three-character device STC takes priority over S
	device, offset, isBit, err = parseAddr("STC3")
	assert.Nil(t, err)
	assert.Equal(t, "STC", device)
	assert.Equal(t, 3, offset)
	assert.True(t, isBit)

	// Lowercase compatibility
	device, _, _, err = parseAddr("d50")
	assert.Nil(t, err)
	assert.Equal(t, "D", device)

	// Invalid input
	_, _, _, err = parseAddr("")
	assert.NotNil(t, err)
	_, _, _, err = parseAddr("ZZ1")
	assert.NotNil(t, err)
	_, _, _, err = parseAddr("D")
	assert.NotNil(t, err)
	_, _, _, err = parseAddr("D1.5")
	assert.NotNil(t, err)
}

// TestWordCount type -> word count mapping
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

// TestDecodeEncodeWords word sequence encoding/decoding (MELSEC native byte order: little-endian within word, low word first)
func TestDecodeEncodeWords(t *testing.T) {
	// INT16 negative number
	v, err := decodeWords([]uint16{0xFFFF}, "INT16")
	assert.Nil(t, err)
	assert.Equal(t, int16(-1), v)

	// UINT16
	v, _ = decodeWords([]uint16{0xABCD}, "UINT16")
	assert.Equal(t, uint16(0xABCD), v)

	// Empty type treated as INT16
	v, _ = decodeWords([]uint16{5}, "")
	assert.Equal(t, int16(5), v)

	// BOOL
	v, _ = decodeWords([]uint16{1}, "BOOL")
	assert.Equal(t, true, v)

	// INT32: low word first (-123456 = 0xFFFE1DC0 -> low word 0x1DC0 high word 0xFFFE)
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

	// encode INT16 negative number
	words, err = encodeValue("-1", "INT16")
	assert.Nil(t, err)
	assert.Equal(t, uint16(0xFFFF), words[0])

	// Invalid value
	_, err = encodeValue("abc", "INT16")
	assert.NotNil(t, err)
	_, err = encodeValue("1", "STRING")
	assert.NotNil(t, err)
}

// mockPLC in-process MC protocol 3E frame (binary) PLC simulator
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

// handle reads and responds to requests frame by frame (3E frame: 9-byte header + data)
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

// dispatch parses request body and generates response.
// Request body: timer(2) cmd(2) subcmd(2) | addr(3) devcode(1) count(2) [data]
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
	case cmd == 0x0401 && subcmd == 0x0000: // Word batch read
		payload = m.readWords(dev, addr, count)
	case cmd == 0x0401 && subcmd == 0x0001: // Bit batch read
		payload = m.readBits(dev, addr, count)
	case cmd == 0x1401 && subcmd == 0x0000: // Word batch write
		m.writeWords(dev, addr, body[12:])
	case cmd == 0x1401 && subcmd == 0x0001: // Bit batch write
		m.writeBits(dev, addr, body[12:], count)
	default:
		endCode = 0x0002
	}
	return m.frame(endCode, payload)
}

// frame assembles 3E response frame: D0 00 header + length + endcode + payload
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

// readBits packs bit reads: even bits in high nibble, odd bits in low nibble (consistent with gomcprotocol decoding)
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

// Preload/read storage (test helper)
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

// TestDriverReadWriteEndToEnd driver layer end-to-end: write then read back (word/bit/multiword type/engineering conversion)
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

	// Write multi-type points
	err = d.WritePoints([]iot_points.Point{
		{Name: "Temperature", Addr: "D100", Type: "FLOAT32", Value: "23.5"},
		{Name: "Counter", Addr: "D200", Type: "INT32", Value: "-123456"},
		{Name: "Flag", Addr: "M5", Type: "BOOL", Value: "true"},
		{Name: "File", Addr: "R10", Type: "UINT16", Value: "0x1234"},
		{Name: "Link", Addr: "W8", Type: "INT16", Value: "-5"},
	})
	assert.Nil(t, err)

	// Read back verification
	datas, err := d.ReadPoints([]iot_points.Point{
		{Name: "Temperature", Addr: "D100", Type: "FLOAT32"},
		{Name: "Counter", Addr: "D200", Type: "INT32"},
		{Name: "Flag", Addr: "M5", Type: "BOOL"},
		{Name: "File", Addr: "R10", Type: "UINT16"},
		{Name: "Link", Addr: "W8", Type: "INT16"},
	})
	assert.Nil(t, err)
	assert.Equal(t, 5, len(datas))
	assert.Equal(t, float32(23.5), datas[0].Value)
	assert.Equal(t, int32(-123456), datas[1].Value)
	assert.Equal(t, true, datas[2].Value)
	assert.Equal(t, uint16(0x1234), datas[3].Value)
	assert.Equal(t, int16(-5), datas[4].Value)

	// Engineering conversion: D300 raw 100, scale=0.1 offset=2 -> 12
	plc.setWords(devD, 300, 100)
	datas, err = d.ReadPoints([]iot_points.Point{
		{Name: "Converted", Addr: "D300", Type: "UINT16", Scale: 0.1, Offset: 2},
	})
	assert.Nil(t, err)
	assert.Equal(t, 100*0.1+2, datas[0].Value)

	// Single point failure marks Error, successful points return normally
	datas, err = d.ReadPoints([]iot_points.Point{
		{Name: "Invalid", Addr: "ZZ1", Type: "UINT16"},
		{Name: "Valid", Addr: "D300", Type: "UINT16"},
	})
	assert.Nil(t, err)
	assert.True(t, datas[0].Error != "")
	assert.Equal(t, uint16(100), datas[1].Value)

	// All failures return error
	_, err = d.ReadPoints([]iot_points.Point{{Name: "Invalid", Addr: "ZZ1"}})
	assert.NotNil(t, err)
}

// TestMcReadNodeEndToEnd mcRead node end-to-end: connect mock PLC -> read points -> output Data list.
// msg.Data points take priority over configured points (dual entry).
func TestMcReadNodeEndToEnd(t *testing.T) {
	plc := startMockPLC(t)
	defer plc.close()
	// Preload D100=23.5(FLOAT32), D200=777
	plc.setWords(devD, 100, split32(math.Float32bits(23.5))...)
	plc.setWords(devD, 200, 777)
	plc.setBit(devM, 0, true)

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/mcRead", types.Configuration{
		"server":  plc.addr(),
		"timeout": 5,
		"points": []map[string]interface{}{
			{"name": "Temperature", "addr": "D100", "type": "FLOAT32"},
			{"name": "Running", "addr": "M0", "type": "BOOL"},
		},
	}, registry)
	assert.Nil(t, err)

	// Configured points entry
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: `{}`}},
		func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.True(t, strings.Contains(msg.GetData(), "Temperature"))
			assert.True(t, strings.Contains(msg.GetData(), "23.5"))
			assert.True(t, strings.Contains(msg.GetData(), "Running"))
			done <- struct{}{}
		})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for mc read callback")
	}

	// msg.Data points entry priority (read D200 instead of configured temperature/running)
	done2 := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST",
		Data: `[{"name":"Counter","addr":"D200","type":"UINT16"}]`}},
		func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.True(t, strings.Contains(msg.GetData(), "Counter"))
			assert.True(t, strings.Contains(msg.GetData(), "777"))
			done2 <- struct{}{}
		})
	select {
	case <-done2:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for mc read (msg.Data points) callback")
	}
}

// TestMcWriteNodeEndToEnd mcWrite node end-to-end: read points from msg.Data -> write mock PLC -> verify storage.
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
	writePayload := `[{"name":"Counter","addr":"D10","type":"UINT16","value":"4321"},{"name":"Running","addr":"M0","type":"BOOL","value":"true"},{"name":"Temperature","addr":"D20","type":"FLOAT32","value":"65.5"}]`
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

// TestMcReadFailureNoPLC connection fails when no PLC, node goes to Failure chain
func TestMcReadFailureNoPLC(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/mcRead", types.Configuration{
		"server":  "127.0.0.1:19999",
		"timeout": 1,
		"points": []map[string]interface{}{
			{"name": "Temperature", "addr": "D100", "type": "FLOAT32"},
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
