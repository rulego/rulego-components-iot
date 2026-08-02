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

// Package finsclient implements Omron FINS protocol client (CS/CJ/CP/NJ/NX series PLCs),
// supporting both FINS/UDP and FINS/TCP transports. Pure standard library implementation,
// synchronous request/response pairing, no background goroutine.
//
// Memory area codes follow W342 FINS Commands Reference (CS/CJ series) standard values,
// where word code = bit code | 0x80:
// CIO=0x30/0xB0, WR=0x31/0xB1, HR=0x32/0xB2, AR=0x33/0xB3, DM=0x02/0x03.

package finsclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Memory area codes (word/bit), commands 0x0101/0x0102, CS/CJ/CP/NSJ series.
// Relay area word code = bit code | 0x80 (0x3x bit / 0xBx word), DM uses legacy reserved code (0x02/0x03).
// Based on W342 command reference and PcVue/KEPware commercial driver code tables;
// verify by reading H/A/CIO once before real device deployment.
const (
	MemoryAreaDMWord  byte = 0x02
	MemoryAreaDMBit   byte = 0x03
	MemoryAreaCIOBit  byte = 0x30
	MemoryAreaWRBit   byte = 0x31
	MemoryAreaHRBit   byte = 0x32
	MemoryAreaARBit   byte = 0x33
	MemoryAreaCIOWord byte = 0xB0
	MemoryAreaWRWord  byte = 0xB1
	MemoryAreaHRWord  byte = 0xB2
	MemoryAreaARWord  byte = 0xB3
)

// Command and frame constants
const (
	cmdMemoryAreaRead  uint16 = 0x0101
	cmdMemoryAreaWrite uint16 = 0x0102

	// defaultPort FINS default port (both UDP and TCP are 9600)
	defaultPort = 9600
	// defaultTimeout default request timeout
	defaultTimeout = 5 * time.Second
	// maxFrameSize max single frame size
	maxFrameSize = 65535
)

// FINS/TCP frame header constants
var finsTCPHeader = []byte("FINS")

const (
	// tcpCmdNodeAddress FINS/TCP node address negotiation command
	tcpCmdNodeAddress uint32 = 0x00000000
	// tcpCmdSendFrame FINS/TCP frame send command
	tcpCmdSendFrame uint32 = 0x00000002
	// tcpHeaderSize FINS/TCP frame header length
	tcpHeaderSize = 16
)

// Address FINS node address
type Address struct {
	// Host PLC address (IP or hostname)
	Host string
	// Port port, 0 uses default 9600
	Port int
	// Network FINS network number (DNA/SNA)
	Network byte
	// Node FINS node number (DA1/SA1; negotiated by handshake in TCP)
	Node byte
	// Unit unit address (DA2)
	Unit byte
}

// NewAddress constructs FINS node address
func NewAddress(host string, port int, network, node, unit byte) Address {
	if port == 0 {
		port = defaultPort
	}
	return Address{Host: host, Port: port, Network: network, Node: node, Unit: unit}
}

// Client FINS client. Concurrent-safe: internal mutex serializes request-response pairing.
type Client struct {
	src     Address
	dst     Address
	tcp     bool
	timeout time.Duration

	mu      sync.Mutex
	conn    net.Conn
	sid     byte
	readBuf [maxFrameSize]byte // UDP read buffer reuse (exchange serial access)
	closed  atomic.Bool
}

// Option optional configuration
type Option func(*Client)

// WithTCP uses FINS/TCP transport (default FINS/UDP)
func WithTCP() Option {
	return func(c *Client) { c.tcp = true }
}

// WithTimeout sets request timeout
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// NewClient creates and connects FINS client. TCP transport automatically completes node address negotiation.
func NewClient(local, plc Address, opts ...Option) (*Client, error) {
	c := &Client{
		src:     local,
		dst:     plc,
		timeout: defaultTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	if c.dst.Port == 0 {
		c.dst.Port = defaultPort
	}
	addr := net.JoinHostPort(c.dst.Host, strconv.Itoa(c.dst.Port))
	if c.tcp {
		conn, err := net.DialTimeout("tcp", addr, c.timeout)
		if err != nil {
			return nil, fmt.Errorf("fins tcp dial %s: %w", addr, err)
		}
		c.conn = conn
		if err := c.tcpHandshake(); err != nil {
			conn.Close()
			return nil, err
		}
	} else {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("fins udp resolve %s: %w", addr, err)
		}
		laddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		conn, err := net.DialUDP("udp", laddr, raddr)
		if err != nil {
			return nil, fmt.Errorf("fins udp dial %s: %w", addr, err)
		}
		c.conn = conn
	}
	return c, nil
}

// Close closes connection
func (c *Client) Close() error {
	c.closed.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ReadWords reads word area, returns count big-endian words
func (c *Client) ReadWords(area byte, address, count uint16) ([]uint16, error) {
	payload := buildMemAreaPayload(cmdMemoryAreaRead, area, address, 0, count, nil)
	data, err := c.exchange(payload)
	if err != nil {
		return nil, err
	}
	if len(data) < int(count)*2 {
		return nil, fmt.Errorf("fins read: short response %d bytes for %d words", len(data), count)
	}
	words := make([]uint16, count)
	for i := range words {
		words[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
	}
	return words, nil
}

// ReadBits reads bit area, each bit occupies 1 byte (0/1)
func (c *Client) ReadBits(area byte, address uint16, bitOffset byte, count uint16) ([]bool, error) {
	payload := buildMemAreaPayload(cmdMemoryAreaRead, area, address, bitOffset, count, nil)
	data, err := c.exchange(payload)
	if err != nil {
		return nil, err
	}
	if len(data) < int(count) {
		return nil, fmt.Errorf("fins read bits: short response %d bytes for %d bits", len(data), count)
	}
	bits := make([]bool, count)
	for i := range bits {
		bits[i] = data[i]&0x01 != 0
	}
	return bits, nil
}

// WriteWords writes word area (big-endian)
func (c *Client) WriteWords(area byte, address uint16, words []uint16) error {
	data := make([]byte, len(words)*2)
	for i, w := range words {
		binary.BigEndian.PutUint16(data[i*2:i*2+2], w)
	}
	payload := buildMemAreaPayload(cmdMemoryAreaWrite, area, address, 0, uint16(len(words)), data)
	_, err := c.exchange(payload)
	return err
}

// WriteBits writes bit area, each bit occupies 1 byte (0x00/0x01)
func (c *Client) WriteBits(area byte, address uint16, bitOffset byte, bits []bool) error {
	data := make([]byte, len(bits))
	for i, b := range bits {
		if b {
			data[i] = 0x01
		}
	}
	payload := buildMemAreaPayload(cmdMemoryAreaWrite, area, address, bitOffset, uint16(len(bits)), data)
	_, err := c.exchange(payload)
	return err
}

// buildMemAreaPayload constructs memory area read/write command payload: MRC SRC + area code(1) + word address(2) + bit offset(1) + count(2) [+ data]
func buildMemAreaPayload(cmd uint16, area byte, address uint16, bitOffset byte, count uint16, data []byte) []byte {
	payload := make([]byte, 8, 8+len(data))
	binary.BigEndian.PutUint16(payload[0:2], cmd)
	payload[2] = area
	binary.BigEndian.PutUint16(payload[3:5], address)
	payload[5] = bitOffset
	binary.BigEndian.PutUint16(payload[6:8], count)
	return append(payload, data...)
}

// buildFrame constructs FINS frame: ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID + command payload
func (c *Client) buildFrame(sid byte, payload []byte) []byte {
	frame := make([]byte, 10, 10+len(payload))
	frame[0] = 0x80 // Command frame, requires response
	frame[1] = 0x00
	frame[2] = 0x02 // GCT
	frame[3] = c.dst.Network
	frame[4] = c.dst.Node
	frame[5] = c.dst.Unit
	frame[6] = c.src.Network
	frame[7] = c.src.Node
	frame[8] = c.src.Unit
	frame[9] = sid
	return append(frame, payload...)
}

// exchange sends one frame and waits for matching SID response, returns response data segment (after MRC SRC MRES SRES).
// UDP reads single packet; TCP first reads 16-byte frame header then payload by length. Non-matching SID responses are discarded and retried.
func (c *Client) exchange(payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return nil, errors.New("fins client closed")
	}
	if c.conn == nil {
		return nil, errors.New("fins client not connected")
	}
	c.sid++
	sid := c.sid

	send := c.buildFrame(sid, payload)
	deadline := time.Now().Add(c.timeout)
	if c.tcp {
		send = wrapTCPFrame(tcpCmdSendFrame, send)
	}
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(send); err != nil {
		return nil, fmt.Errorf("fins write: %w", err)
	}
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	for {
		frame, err := c.readFrame()
		if err != nil {
			return nil, fmt.Errorf("fins read: %w", err)
		}
		// Discard non-response frames: too-short frames (FINS/TCP heartbeat/empty payload) and SID-mismatched frames
		if len(frame) < 14 || frame[9] != sid {
			continue
		}
		endCode := binary.BigEndian.Uint16(frame[12:14])
		if endCode != 0 {
			return nil, fmt.Errorf("fins command rejected, end code 0x%04X", endCode)
		}
		return frame[14:], nil
	}
}

// readFrame reads one FINS frame (UDP is single packet; TCP parses 16-byte frame header and extracts payload)
func (c *Client) readFrame() ([]byte, error) {
	if !c.tcp {
		n, err := c.conn.Read(c.readBuf[:])
		if err != nil {
			return nil, err
		}
		return c.readBuf[:n], nil
	}
	header := make([]byte, tcpHeaderSize)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[4:8])
	if length < 8 || length-8 > maxFrameSize {
		return nil, fmt.Errorf("fins tcp invalid frame length %d", length)
	}
	payload := make([]byte, length-8)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}
	// Non-frame-send commands (e.g. node address echo) not handled here, consumed by handshake stage
	return payload, nil
}

// wrapTCPFrame wraps FINS/TCP frame header: "FINS" + length(4) + command(4) + error code(4) + payload
func wrapTCPFrame(command uint32, payload []byte) []byte {
	frame := make([]byte, tcpHeaderSize, tcpHeaderSize+len(payload))
	copy(frame[0:4], finsTCPHeader)
	binary.BigEndian.PutUint32(frame[4:8], uint32(8+len(payload)))
	binary.BigEndian.PutUint32(frame[8:12], command)
	binary.BigEndian.PutUint32(frame[12:16], 0)
	return append(frame, payload...)
}

// tcpHandshake FINS/TCP node address negotiation: sends local address, peer responds with its address + assigned local address.
// Negotiation result written to dst.Node (DA1) and src.Node (SA1).
func (c *Client) tcpHandshake() error {
	clientAddr := []byte{c.src.Network, 0, 0, c.src.Node}
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	if _, err := c.conn.Write(wrapTCPFrame(tcpCmdNodeAddress, clientAddr)); err != nil {
		return fmt.Errorf("fins tcp handshake write: %w", err)
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	header := make([]byte, tcpHeaderSize)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return fmt.Errorf("fins tcp handshake read: %w", err)
	}
	if string(header[0:4]) != "FINS" {
		return errors.New("fins tcp handshake: invalid header magic")
	}
	cmd := binary.BigEndian.Uint32(header[8:12])
	if cmd != tcpCmdNodeAddress {
		return fmt.Errorf("fins tcp handshake: unexpected command 0x%08X", cmd)
	}
	length := binary.BigEndian.Uint32(header[4:8])
	if length < 8 || length-8 > 1024 {
		return fmt.Errorf("fins tcp handshake: invalid length %d", length)
	}
	payload := make([]byte, length-8)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return fmt.Errorf("fins tcp handshake read payload: %w", err)
	}
	if len(payload) >= 4 {
		c.dst.Node = payload[3] // Peer node number
	}
	if len(payload) >= 8 && payload[7] != 0 {
		c.src.Node = payload[7] // Local node number assigned by peer
	}
	return nil
}
