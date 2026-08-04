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

// TestFinsNodes node types and default configurations
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

// TestParseAddr Omron memory area address parsing (including CIO area).
func TestParseAddr(t *testing.T) {
	cases := []struct {
		addr      string
		area      byte
		address   uint16
		bitOffset byte
		isBit     bool
	}{
		{"CIO100", finsclient.MemoryAreaCIOWord, 100, 0, false},
		{"cio0", finsclient.MemoryAreaCIOWord, 0, 0, false}, // case-insensitive
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
		area, address, bitOffset, isBit, strLen, err := parseAddr(c.addr)
		assert.Nil(t, err, c.addr)
		assert.Equal(t, c.area, area, c.addr)
		assert.Equal(t, c.address, address, c.addr)
		assert.Equal(t, c.bitOffset, bitOffset, c.addr)
		assert.Equal(t, c.isBit, isBit, c.addr)
		assert.Equal(t, 0, strLen, c.addr)
	}
}

// TestParseAddrString STRING byte length suffix (:N) resolves to word area + strLen.
func TestParseAddrString(t *testing.T) {
	area, address, _, isBit, strLen, err := parseAddr("D100:20")
	assert.Nil(t, err)
	assert.Equal(t, finsclient.MemoryAreaDMWord, area)
	assert.Equal(t, uint16(100), address)
	assert.False(t, isBit)
	assert.Equal(t, 20, strLen)
}

// TestParseAddrError invalid addresses.
func TestParseAddrError(t *testing.T) {
	bad := []string{"", "X100", "D", "D1.2.3", "D65536"}
	for _, addr := range bad {
		_, _, _, _, _, err := parseAddr(addr)
		assert.NotNil(t, err, addr)
	}
}

// TestWordConversion word order conversion round-trip.
func TestWordConversion(t *testing.T) {
	assert.Equal(t, uint32(0x12345678), wordsToUint32([]uint16{0x1234, 0x5678}))
	assert.Equal(t, []uint16{0x1234, 0x5678}, uint32ToWords(0x12345678))
	assert.Equal(t, uint64(0x1122334455667788), wordsToUint64([]uint16{0x1122, 0x3344, 0x5566, 0x7788}))
	assert.Equal(t, []uint16{0x1122, 0x3344, 0x5566, 0x7788}, uint64ToWords(0x1122334455667788))
}

// TestEncodeDecodeWords encoding/decoding round-trip for various types.
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

	// Signed type negative value encoding/decoding
	roundTrip("INT16", "-1")
	roundTrip("INT32", "-100000")
	roundTrip("INT64", "-1234567890123")

	// FLOAT32 encoding/decoding accuracy
	w, _ := encodeWords("FLOAT32", "23.5")
	val, _ := decodeWords("FLOAT32", w)
	assert.Equal(t, float32(23.5), val)

	// INT16 negative value encoding/decoding accuracy
	w, _ = encodeWords("INT16", "-2")
	val, _ = decodeWords("INT16", w)
	assert.Equal(t, int16(-2), val)

	// Unknown type and STRING not supported
	_, err := encodeWords("STRING", "abc")
	assert.NotNil(t, err)
	_, err = wordCount("CUSTOM")
	assert.NotNil(t, err)
}

// TestParseBoolValue boolean value parsing.
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

// --- in-process FINS PLC simulator (word/bit areas, standard W342 area codes) ---

// mockPLC maintains word/bit storage by memory area code
type mockPLC struct {
	mu    sync.Mutex
	words map[byte][]byte
	bits  map[byte][]byte
	// rejectMultiple 0x0104 commands rejected with "undefined command" end code
	rejectMultiple bool
	// truncateMultiple drops the last item's data so the 0x0104 response is short (non-end-code error)
	truncateMultiple bool
	// requests total handled command frames
	requests int
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

// handle processes one FINS command frame, returns complete response frame
func (m *mockPLC) handle(frame []byte) []byte {
	// 12 = FINS header (10) + command code (2); 0x0104 single-item frames are 16 bytes.
	// 0x0101/0x0102 frames are 18 bytes and access frame[12:18] in their own branch below.
	if len(frame) < 12 {
		return nil
	}
	resp := make([]byte, 14)
	copy(resp[0:10], frame[0:10])
	resp[0] = 0xC0 // Response frame
	resp[3], resp[6] = frame[6], frame[3]
	resp[4], resp[7] = frame[7], frame[4]
	resp[5], resp[8] = frame[8], frame[5]
	resp[10] = frame[10] // MRC
	resp[11] = frame[11] // SRC
	resp[12] = 0         // MRES
	resp[13] = 0         // SRES

	cmd := binary.BigEndian.Uint16(frame[10:12])

	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++

	if cmd == 0x0104 {
		return m.handleMultiple(frame, resp)
	}

	area := frame[12]
	addr := int(binary.BigEndian.Uint16(frame[13:15]))
	bitOff := int(frame[15])
	count := int(binary.BigEndian.Uint16(frame[16:18]))

	isBit := m.bits[area] != nil
	store := m.words[area]
	if isBit {
		store = m.bits[area]
	}
	if store == nil {
		resp[12] = 0x22 // Unsupported memory area
		return resp
	}
	switch cmd {
	case 0x0101: // Read
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
	case 0x0102: // Write
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

// handleMultiple processes 0x0104 multiple memory area read: items are 4 bytes each {area(1) address(2) bit(1)};
// response data is per item {area echo(1) + data(word 2 bytes / bit 1 byte)}.
func (m *mockPLC) handleMultiple(frame, resp []byte) []byte {
	if m.rejectMultiple {
		resp[12] = 0x04 // end code 0x0401 undefined command
		resp[13] = 0x01
		return resp
	}
	items := frame[12:]
	if len(items)%4 != 0 {
		resp[12] = 0x20 // end code 0x2001 command format error
		resp[13] = 0x01
		return resp
	}
	for off := 0; off < len(items); off += 4 {
		area := items[off]
		addr := int(binary.BigEndian.Uint16(items[off+1 : off+3]))
		bitOff := int(items[off+3])
		resp = append(resp, area)
		if store := m.words[area]; store != nil {
			start := addr * 2
			if start+2 > len(store) {
				resp[12] = 0x23
				return resp
			}
			resp = append(resp, store[start:start+2]...)
		} else if store := m.bits[area]; store != nil {
			start := addr + bitOff
			if start >= len(store) {
				resp[12] = 0x23
				return resp
			}
			resp = append(resp, store[start]&0x01)
		} else {
			resp[12] = 0x22
			return resp
		}
	}
	if m.truncateMultiple && len(resp) > 16 {
		resp = resp[:len(resp)-2] // drop last word item's data -> short response (non-end-code error)
	}
	return resp
}

// startUDPSimulator starts in-process FINS/UDP PLC simulator, returns address and cleanup function
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

// startTCPSimulator starts in-process FINS/TCP PLC simulator (with node address handshake), returns address and cleanup function
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
				// Handshake: server node 21, assign client node 17
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

// newTestClient creates FINS client (UDP) pointing to simulator.
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

// TestFinsDriverE2E driver end-to-end: write-then-read + Scale engineering conversion + CIO area.
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

// TestFinsReadNode finsRead node end-to-end: connect simulator -> read D area -> output Data list.
func TestFinsReadNode(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()

	// First write D100=4321
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

// TestFinsReadNodeTCP finsRead node FINS/TCP transport end-to-end (with handshake).
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

// TestFinsWriteNode finsWrite node end-to-end: msg.Data points (precedence over config) -> write to simulator -> read back verification.
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

	// Read back verification
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

// TestApplyEndian byte/word reorder transforms (ABCD no-op, CDAB/BADC/DCBA), all involutions.
func TestApplyEndian(t *testing.T) {
	orig := []uint16{0x1234, 0x5678}
	assert.Equal(t, orig, applyEndian(orig, "ABCD"))
	assert.Equal(t, orig, applyEndian(orig, "")) // empty = ABCD

	// CDAB = word swap
	assert.Equal(t, []uint16{0x5678, 0x1234}, applyEndian(orig, "CDAB"))
	// BADC = intra-word byte swap
	assert.Equal(t, []uint16{0x3412, 0x7856}, applyEndian(orig, "BADC"))
	// DCBA = both
	assert.Equal(t, []uint16{0x7856, 0x3412}, applyEndian(orig, "DCBA"))

	// Involution: applying twice restores the original
	for _, e := range []string{"CDAB", "BADC", "DCBA"} {
		assert.Equal(t, orig, applyEndian(applyEndian(orig, e), e), e)
	}
	// Four words: DCBA reverses byte order of the whole sequence
	assert.Equal(t, []uint16{0xf0de, 0xbc9a, 0x7856, 0x3412},
		applyEndian([]uint16{0x1234, 0x5678, 0x9abc, 0xdef0}, "DCBA"))
}

// TestStringWords STRING encode/decode: even length, odd length zero-pad, NUL trimming, truncation.
func TestStringWords(t *testing.T) {
	// Even length: 6 bytes = 3 words, value shorter padded with NUL
	w := encodeStringWords("AB", 6)
	assert.Equal(t, []uint16{0x4142, 0x0000, 0x0000}, w)
	assert.Equal(t, "AB", decodeString(wordsToBytes(w)))

	// Odd length: 5 bytes = ceil to 3 words (6 bytes), trailing byte padded zero
	w = encodeStringWords("ABCDE", 5)
	assert.Equal(t, []uint16{0x4142, 0x4344, 0x4500}, w)
	assert.Equal(t, "ABCDE", decodeString(wordsToBytes(w)[:5]))

	// Value longer than strLen: truncated
	w = encodeStringWords("ABCDEFGH", 4)
	assert.Equal(t, []uint16{0x4142, 0x4344}, w)
	assert.Equal(t, "ABCD", decodeString(wordsToBytes(w)[:4]))

	// NUL terminator trimming
	assert.Equal(t, "OK", decodeString([]byte("OK\x00")))
}

// TestFinsStringRoundTrip STRING write+read round-trip via simulator (even and odd lengths).
func TestFinsStringRoundTrip(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	client := newTestClient(t, addr)
	defer client.Close()
	d := newDriver(client)

	cases := []struct {
		name  string
		addr  string
		value string
	}{
		{"s4", "D100:4", "ABCD"},
		{"s6", "D200:6", "Hello"},
		{"s11", "D300:11", "12345678901"}, // odd length
	}
	for _, c := range cases {
		assert.Nil(t, d.WritePoints([]iot_points.Point{
			{Name: c.name, Addr: c.addr, Type: "STRING", Value: c.value},
		}), c.name)
	}
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "s4", Addr: "D100:4", Type: "STRING"},
		{Name: "s6", Addr: "D200:6", Type: "STRING"},
		{Name: "s11", Addr: "D300:11", Type: "STRING"},
	})
	assert.Nil(t, err)
	assert.Equal(t, "ABCD", data[0].Value)
	assert.Equal(t, "Hello", data[1].Value)
	assert.Equal(t, "12345678901", data[2].Value)
}

// TestFinsEndianRead reads multi-word points seeded with known raw bytes, asserting each endian transform.
// Raw bytes at D100-D101: 78 56 34 12 -> words [0x7856, 0x3412]
func TestFinsEndianRead(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	seed := newTestClient(t, addr)
	defer seed.Close()
	assert.Nil(t, seed.WriteWords(finsclient.MemoryAreaDMWord, 100, []uint16{0x7856, 0x3412}))

	d := newDriver(seed)
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "abcd", Addr: "D100", Type: "UINT32", Endian: "ABCD"},
		{Name: "cdab", Addr: "D100", Type: "UINT32", Endian: "CDAB"},
		{Name: "badc", Addr: "D100", Type: "UINT32", Endian: "BADC"},
		{Name: "dcba", Addr: "D100", Type: "UINT32", Endian: "DCBA"},
	})
	assert.Nil(t, err)
	assert.Equal(t, uint32(0x78563412), data[0].Value)
	assert.Equal(t, uint32(0x34127856), data[1].Value)
	assert.Equal(t, uint32(0x56781234), data[2].Value)
	assert.Equal(t, uint32(0x12345678), data[3].Value)
}

// TestFinsEndianWrite endian write round-trip: write then read back with same endian.
func TestFinsEndianWrite(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	client := newTestClient(t, addr)
	defer client.Close()
	d := newDriver(client)

	for _, e := range []string{"ABCD", "CDAB", "BADC", "DCBA"} {
		assert.Nil(t, d.WritePoints([]iot_points.Point{
			{Name: "v", Addr: "D200", Type: "INT32", Value: "-1000", Endian: e},
		}), e)
		data, err := d.ReadPoints([]iot_points.Point{
			{Name: "v", Addr: "D200", Type: "INT32", Endian: e},
		})
		assert.Nil(t, err, e)
		assert.Equal(t, int32(-1000), data[0].Value, e)
	}
}

// TestFinsBatchRead multiple points across areas read in a single 0x0104 frame.
func TestFinsBatchRead(t *testing.T) {
	plc, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	client := newTestClient(t, addr)
	defer client.Close()
	d := newDriver(client)

	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16", Value: "1234"},
		{Name: "i32", Addr: "D200", Type: "INT32", Value: "100000"},
		{Name: "cio", Addr: "CIO50", Type: "UINT16", Value: "777"},
		{Name: "bit", Addr: "D0.5", Type: "BOOL", Value: "true"},
		{Name: "str", Addr: "D300:5", Type: "STRING", Value: "hello"},
	}))

	plc.mu.Lock()
	before := plc.requests
	plc.mu.Unlock()

	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16"},
		{Name: "i32", Addr: "D200", Type: "INT32"},
		{Name: "cio", Addr: "CIO50", Type: "UINT16"},
		{Name: "bit", Addr: "D0.5", Type: "BOOL"},
		{Name: "str", Addr: "D300:5", Type: "STRING"},
	})
	assert.Nil(t, err)
	assert.Equal(t, 5, len(data))
	assert.Equal(t, uint16(1234), data[0].Value)
	assert.Equal(t, int32(100000), data[1].Value)
	assert.Equal(t, uint16(777), data[2].Value)
	assert.Equal(t, true, data[3].Value)
	assert.Equal(t, "hello", data[4].Value)

	// One 0x0104 frame for all 5 points (u16=1 + i32=2 + cio=1 + bit=1 + str=3 = 8 items)
	plc.mu.Lock()
	assert.Equal(t, 1, plc.requests-before)
	plc.mu.Unlock()
}

// TestFinsBatchFallback PLC rejects 0x0104; points still read correctly via per-point 0x0101 fallback.
func TestFinsBatchFallback(t *testing.T) {
	plc, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	client := newTestClient(t, addr)
	defer client.Close()
	d := newDriver(client)

	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16", Value: "1234"},
		{Name: "i32", Addr: "D200", Type: "INT32", Value: "100000"},
	}))

	plc.mu.Lock()
	plc.rejectMultiple = true
	before := plc.requests
	plc.mu.Unlock()

	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16"},
		{Name: "i32", Addr: "D200", Type: "INT32"},
	})
	assert.Nil(t, err)
	assert.Equal(t, uint16(1234), data[0].Value)
	assert.Equal(t, int32(100000), data[1].Value)

	// 1 rejected batch + 2 per-point reads = 3 frames
	plc.mu.Lock()
	assert.Equal(t, 3, plc.requests-before)
	plc.mu.Unlock()
}

// TestFinsBatchNoFallbackOnShortResponse a non-end-code error (truncated 0x0104 response) must NOT fall back to
// per-point reads: all points are marked failed from the single batch attempt (no N-fold timeout amplification).
func TestFinsBatchNoFallbackOnShortResponse(t *testing.T) {
	plc, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	client := newTestClient(t, addr)
	defer client.Close()
	d := newDriver(client)

	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16", Value: "1234"},
		{Name: "i32", Addr: "D200", Type: "INT32", Value: "100000"},
	}))

	plc.mu.Lock()
	plc.truncateMultiple = true
	before := plc.requests
	plc.mu.Unlock()

	_, err := d.ReadPoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16"},
		{Name: "i32", Addr: "D200", Type: "INT32"},
	})
	// All points failed in one batch -> ReadPoints returns error; no per-point 0x0101 fallback
	assert.NotNil(t, err)

	plc.mu.Lock()
	assert.Equal(t, 1, plc.requests-before) // single 0x0104 attempt, no per-point 0x0101
	plc.mu.Unlock()
}

// TestFinsSingleWordEndianIgnored single-word points ignore Endian (contract: multi-register types only).
func TestFinsSingleWordEndianIgnored(t *testing.T) {
	_, addr, cleanup := startUDPSimulator(t)
	defer cleanup()
	client := newTestClient(t, addr)
	defer client.Close()
	d := newDriver(client)

	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16", Value: "4660"}, // 0x1234
	}))
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "u16", Addr: "D100", Type: "UINT16", Endian: "BADC"}, // single word: endian ignored
	})
	assert.Nil(t, err)
	assert.Equal(t, uint16(0x1234), data[0].Value)
}
