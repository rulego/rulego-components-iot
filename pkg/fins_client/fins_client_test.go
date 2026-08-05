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

package finsclient

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rulego/rulego/test/assert"
)

// TestBuildMemAreaPayload read/write command payload byte layout
func TestBuildMemAreaPayload(t *testing.T) {
	p := buildMemAreaPayload(cmdMemoryAreaRead, MemoryAreaDMWord, 100, 0, 4, nil)
	assert.Equal(t, 8, len(p))
	assert.Equal(t, byte(0x01), p[0]) // MRC
	assert.Equal(t, byte(0x01), p[1]) // SRC
	assert.Equal(t, MemoryAreaDMWord, p[2])
	assert.Equal(t, uint16(100), binary.BigEndian.Uint16(p[3:5]))
	assert.Equal(t, byte(0), p[5]) // Bit offset
	assert.Equal(t, uint16(4), binary.BigEndian.Uint16(p[6:8]))

	p = buildMemAreaPayload(cmdMemoryAreaWrite, MemoryAreaCIOBit, 5, 3, 1, []byte{0x01})
	assert.Equal(t, byte(0x01), p[0])
	assert.Equal(t, byte(0x02), p[1]) // Write command SRC
	assert.Equal(t, MemoryAreaCIOBit, p[2])
	assert.Equal(t, byte(3), p[5])    // Bit offset
	assert.Equal(t, byte(0x01), p[8]) // Write data follows 8-byte command header
}

// TestBuildFrame FINS frame header byte layout
func TestBuildFrame(t *testing.T) {
	c := &Client{
		src: NewAddress("0.0.0.0", 0, 0, 10, 0),
		dst: NewAddress("1.2.3.4", 9600, 0, 20, 0),
	}
	f := c.buildFrame(0x07, []byte{0xAA})
	assert.Equal(t, byte(0x80), f[0]) // ICF command frame
	assert.Equal(t, byte(0x02), f[2]) // GCT
	assert.Equal(t, byte(20), f[4])   // DA1
	assert.Equal(t, byte(10), f[7])   // SA1
	assert.Equal(t, byte(0x07), f[9]) // SID
	assert.Equal(t, byte(0xAA), f[10])
}

// TestWrapTCPFrame FINS/TCP frame header wrapping
func TestWrapTCPFrame(t *testing.T) {
	f := wrapTCPFrame(tcpCmdSendFrame, []byte{1, 2, 3})
	assert.Equal(t, "FINS", string(f[0:4]))
	assert.Equal(t, uint32(11), binary.BigEndian.Uint32(f[4:8])) // 8+3
	assert.Equal(t, tcpCmdSendFrame, binary.BigEndian.Uint32(f[8:12]))
	assert.Equal(t, 19, len(f))
}

// mockPLC in-process FINS PLC simulator: maintains word/bit storage by memory area code, supports UDP and TCP
type mockPLC struct {
	mu    sync.Mutex
	words map[byte][]byte // Word area code -> byte storage
	bits  map[byte][]byte // Bit area code -> bit storage (1 byte per bit)
	// failNext next request returns non-zero end code
	failNext bool
	// rejectMultiple 0x0104 commands rejected with "undefined command" end code
	rejectMultiple bool
	// requests total handled command frames
	requests int
}

func newMockPLC() *mockPLC {
	return &mockPLC{
		words: map[byte][]byte{
			MemoryAreaDMWord:  make([]byte, 2048),
			MemoryAreaCIOWord: make([]byte, 2048),
			MemoryAreaWRWord:  make([]byte, 2048),
			MemoryAreaHRWord:  make([]byte, 2048),
			MemoryAreaARWord:  make([]byte, 2048),
		},
		bits: map[byte][]byte{
			MemoryAreaDMBit:  make([]byte, 2048),
			MemoryAreaCIOBit: make([]byte, 2048),
			MemoryAreaWRBit:  make([]byte, 2048),
			MemoryAreaHRBit:  make([]byte, 2048),
			MemoryAreaARBit:  make([]byte, 2048),
		},
	}
}

// handle processes one FINS command frame, returns complete response frame
func (m *mockPLC) handle(frame []byte) []byte {
	if len(frame) < 10 {
		return nil
	}
	resp := make([]byte, 14)
	copy(resp[0:10], frame[0:10])
	resp[0] = 0xC0 // Response frame
	// Swap source/destination
	resp[3], resp[6] = frame[6], frame[3]
	resp[4], resp[7] = frame[7], frame[4]
	resp[5], resp[8] = frame[8], frame[5]

	cmd := binary.BigEndian.Uint16(frame[10:12])
	resp[10] = frame[10]
	resp[11] = frame[11]
	resp[12] = 0 // MRES
	resp[13] = 0 // SRES

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		m.failNext = false
		resp[12] = 0x21 // Non-zero end code
		return resp
	}
	m.requests++

	if cmd == cmdMultipleMemoryAreaRead {
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
	case cmdMemoryAreaRead:
		if isBit {
			start := addr*0 + addr + bitOff // Bit area linear access by bit address+offset
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
	case cmdMemoryAreaWrite:
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
				return resp[:14]
			}
			resp = append(resp, store[start:start+2]...)
		} else if store := m.bits[area]; store != nil {
			start := addr + bitOff
			if start >= len(store) {
				return resp[:14]
			}
			resp = append(resp, store[start]&0x01)
		} else {
			resp = resp[:14]
			resp[12] = 0x22 // unsupported memory area
			return resp
		}
	}
	return resp
}

// startUDPMock starts UDP mock PLC, returns address and cleanup function
func startUDPMock(t *testing.T) (*mockPLC, string, func()) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free udp port: %v", err)
	}
	plc := newMockPLC()
	go func() {
		buf := make([]byte, maxFrameSize)
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

// startTCPMock starts FINS/TCP mock PLC (includes node address handshake), returns address and cleanup function
func startTCPMock(t *testing.T) (*mockPLC, string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free tcp port: %v", err)
	}
	plc := newMockPLC()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Node address handshake: server replies with Node Address Data Return (0x00000001),
				// carrying client (source) node in payload[3] and server (destination) node in payload[7].
				// Here we confirm the client's node 10 and report the server's node 20.
				handshake := wrapTCPFrame(tcpCmdNodeAddressReturn, []byte{0, 0, 0, 10, 0, 0, 0, 20})
				if _, err := c.Write(handshake); err != nil {
					return
				}
				header := make([]byte, tcpHeaderSize)
				for {
					if _, err := io.ReadFull(c, header); err != nil {
						return
					}
					if !bytes.Equal(header[0:4], finsTCPHeader) {
						return
					}
					length := int(binary.BigEndian.Uint32(header[4:8]))
					payload := make([]byte, length-8)
					if _, err := io.ReadFull(c, payload); err != nil {
						return
					}
					cmd := binary.BigEndian.Uint32(header[8:12])
					if cmd != tcpCmdSendFrame {
						continue
					}
					if resp := plc.handle(payload); resp != nil {
						if _, err := c.Write(wrapTCPFrame(tcpCmdSendFrame, resp)); err != nil {
							return
						}
					}
				}
			}(conn)
		}
	}()
	return plc, l.Addr().String(), func() { l.Close() }
}

// parseHostPort splits 127.0.0.1:port into NewAddress parameters
func parseHostPort(t *testing.T, addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

// TestUDPWordsRoundTrip UDP word area read/write (CIO/DM areas)
func TestUDPWordsRoundTrip(t *testing.T) {
	_, addr, cleanup := startUDPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 10, 0),
		NewAddress(host, port, 0, 20, 0),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	defer client.Close()

	// CIO word area read/write
	assert.Nil(t, client.WriteWords(MemoryAreaCIOWord, 50, []uint16{0x1234, 0xABCD}))
	words, err := client.ReadWords(MemoryAreaCIOWord, 50, 2)
	assert.Nil(t, err)
	assert.Equal(t, uint16(0x1234), words[0])
	assert.Equal(t, uint16(0xABCD), words[1])

	// DM word area read/write
	assert.Nil(t, client.WriteWords(MemoryAreaDMWord, 100, []uint16{250}))
	words, err = client.ReadWords(MemoryAreaDMWord, 100, 1)
	assert.Nil(t, err)
	assert.Equal(t, uint16(250), words[0])
}

// TestUDPBitsRoundTrip UDP bit area read/write (CIO bits)
func TestUDPBitsRoundTrip(t *testing.T) {
	_, addr, cleanup := startUDPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 10, 0),
		NewAddress(host, port, 0, 20, 0),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	defer client.Close()

	assert.Nil(t, client.WriteBits(MemoryAreaCIOBit, 10, 5, []bool{true}))
	bits, err := client.ReadBits(MemoryAreaCIOBit, 10, 5, 1)
	assert.Nil(t, err)
	assert.Equal(t, true, bits[0])

	// Adjacent bits unaffected
	bits, err = client.ReadBits(MemoryAreaCIOBit, 10, 6, 1)
	assert.Nil(t, err)
	assert.Equal(t, false, bits[0])
}

// TestTCPHandshakeAndIO FINS/TCP handshake negotiates node numbers + word area read/write
func TestTCPHandshakeAndIO(t *testing.T) {
	_, addr, cleanup := startTCPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 0, 0),
		NewAddress(host, port, 0, 0, 0),
		WithTCP(),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	defer client.Close()

	// After handshake node numbers negotiated: payload[3]=client(src)=10, payload[7]=server(dst)=20
	assert.Equal(t, byte(10), client.src.Node)
	assert.Equal(t, byte(20), client.dst.Node)

	assert.Nil(t, client.WriteWords(MemoryAreaCIOWord, 0, []uint16{0x77}))
	words, err := client.ReadWords(MemoryAreaCIOWord, 0, 1)
	assert.Nil(t, err)
	assert.Equal(t, uint16(0x77), words[0])
}

// TestEndCodeError non-zero end code returns error
func TestEndCodeError(t *testing.T) {
	plc, addr, cleanup := startUDPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 10, 0),
		NewAddress(host, port, 0, 20, 0),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	defer client.Close()

	plc.mu.Lock()
	plc.failNext = true
	plc.mu.Unlock()

	_, err = client.ReadWords(MemoryAreaDMWord, 0, 1)
	assert.NotNil(t, err)
}

// TestReadMultipleRoundTrip 0x0104 multiple memory area read: mixed word/bit items in one frame
func TestReadMultipleRoundTrip(t *testing.T) {
	plc, addr, cleanup := startUDPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 10, 0),
		NewAddress(host, port, 0, 20, 0),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	defer client.Close()

	assert.Nil(t, client.WriteWords(MemoryAreaDMWord, 100, []uint16{0x1234, 0x5678}))
	assert.Nil(t, client.WriteWords(MemoryAreaCIOWord, 50, []uint16{0xABCD}))
	assert.Nil(t, client.WriteBits(MemoryAreaCIOBit, 50, 3, []bool{true}))

	plc.mu.Lock()
	before := plc.requests
	plc.mu.Unlock()

	out, err := client.ReadMultiple([]MultipleItem{
		{Area: MemoryAreaDMWord, Address: 100},
		{Area: MemoryAreaDMWord, Address: 101},
		{Area: MemoryAreaCIOWord, Address: 50},
		{Area: MemoryAreaCIOBit, Address: 50, Bit: 3},
	})
	assert.Nil(t, err)
	assert.Equal(t, 4, len(out))
	assert.Equal(t, []byte{0x12, 0x34}, out[0])
	assert.Equal(t, []byte{0x56, 0x78}, out[1])
	assert.Equal(t, []byte{0xAB, 0xCD}, out[2])
	assert.Equal(t, []byte{0x01}, out[3]) // bit item: 1 byte

	// All 4 items in one frame
	plc.mu.Lock()
	assert.Equal(t, 1, plc.requests-before)
	plc.mu.Unlock()

	// Empty item list is a no-op
	out, err = client.ReadMultiple(nil)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(out))
}

// TestReadMultipleReject PLC rejecting 0x0104 surfaces as EndCodeError
func TestReadMultipleReject(t *testing.T) {
	plc, addr, cleanup := startUDPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 10, 0),
		NewAddress(host, port, 0, 20, 0),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	defer client.Close()

	plc.mu.Lock()
	plc.rejectMultiple = true
	plc.mu.Unlock()

	_, err = client.ReadMultiple([]MultipleItem{{Area: MemoryAreaDMWord, Address: 0}})
	assert.NotNil(t, err)
	ec, ok := err.(EndCodeError)
	assert.True(t, ok, "error should be EndCodeError")
	assert.Equal(t, uint16(0x0401), uint16(ec))
}

// TestReadMultipleTooManyItems item count over W342 Ethernet limit rejected before I/O
func TestReadMultipleTooManyItems(t *testing.T) {
	_, addr, cleanup := startUDPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 10, 0),
		NewAddress(host, port, 0, 20, 0),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	defer client.Close()

	items := make([]MultipleItem, MaxMultipleReadItems+1)
	for i := range items {
		items[i] = MultipleItem{Area: MemoryAreaDMWord, Address: uint16(i)}
	}
	_, err = client.ReadMultiple(items)
	assert.NotNil(t, err)
}

// TestCloseThenUse using after close returns error
func TestCloseThenUse(t *testing.T) {
	_, addr, cleanup := startUDPMock(t)
	defer cleanup()
	host, port := parseHostPort(t, addr)

	client, err := NewClient(
		NewAddress("0.0.0.0", 0, 0, 10, 0),
		NewAddress(host, port, 0, 20, 0),
		WithTimeout(3*time.Second),
	)
	assert.Nil(t, err)
	assert.Nil(t, client.Close())

	_, err = client.ReadWords(MemoryAreaDMWord, 0, 1)
	assert.NotNil(t, err)
}
