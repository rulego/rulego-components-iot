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

// Package finsclient 实现欧姆龙 FINS 协议客户端(CS/CJ/CP/NJ/NX 系列 PLC)，
// 支持 FINS/UDP 与 FINS/TCP 两种传输。纯标准库实现，请求/响应同步配对，无后台 goroutine。
//
// 内存区代码采用 W342 FINS Commands Reference(CS/CJ 系列)标准值：
// CIO=0x30/0x31、WR=0xB1/0xB2、AR=0xB3/0xB4、HR=0xB4/0xB5、DM=0x02/0x03。
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

// 内存区代码(字/位)，命令 0x0101/0x0102，CS/CJ/CP/NSJ 系列。
// 继电器区字码 = 位码 | 0x80(0x3x 位 / 0xBx 字)，DM 为早期保留码(0x02/0x03)。
// 依据 W342 命令参考与 PcVue/KEPware 等商用驱动码表；真机部署前建议用 H/A/CIO 各读一次核对。
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

// 命令与帧常量
const (
	cmdMemoryAreaRead  uint16 = 0x0101
	cmdMemoryAreaWrite uint16 = 0x0102

	// defaultPort FINS 默认端口(UDP 与 TCP 均为 9600)
	defaultPort = 9600
	// defaultTimeout 默认请求超时
	defaultTimeout = 5 * time.Second
	// maxFrameSize 单帧上限
	maxFrameSize = 65535
)

// FINS/TCP 帧头常量
var finsTCPHeader = []byte("FINS")

const (
	// tcpCmdNodeAddress FINS/TCP 节点地址协商命令
	tcpCmdNodeAddress uint32 = 0x00000000
	// tcpCmdSendFrame FINS/TCP 帧发送命令
	tcpCmdSendFrame uint32 = 0x00000002
	// tcpHeaderSize FINS/TCP 帧头长度
	tcpHeaderSize = 16
)

// Address FINS 节点地址
type Address struct {
	// Host PLC 地址(IP 或主机名)
	Host string
	// Port 端口，0 使用默认 9600
	Port int
	// Network FINS 网络号(DNA/SNA)
	Network byte
	// Node FINS 节点号(DA1/SA1；TCP 下由握手协商)
	Node byte
	// Unit 单元地址(DA2)
	Unit byte
}

// NewAddress 构造 FINS 节点地址
func NewAddress(host string, port int, network, node, unit byte) Address {
	if port == 0 {
		port = defaultPort
	}
	return Address{Host: host, Port: port, Network: network, Node: node, Unit: unit}
}

// Client FINS 客户端。并发安全：内部互斥串行化请求-响应配对。
type Client struct {
	src     Address
	dst     Address
	tcp     bool
	timeout time.Duration

	mu      sync.Mutex
	conn    net.Conn
	sid     byte
	readBuf [maxFrameSize]byte // UDP 读缓冲区复用(exchange 串行访问)
	closed  atomic.Bool
}

// Option 可选配置
type Option func(*Client)

// WithTCP 使用 FINS/TCP 传输(默认 FINS/UDP)
func WithTCP() Option {
	return func(c *Client) { c.tcp = true }
}

// WithTimeout 设置请求超时
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// NewClient 创建并连接 FINS 客户端。TCP 传输自动完成节点地址协商。
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

// Close 关闭连接
func (c *Client) Close() error {
	c.closed.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ReadWords 读字区，返回 count 个大端字
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

// ReadBits 读位区，每个位占 1 字节(0/1)
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

// WriteWords 写字区(大端)
func (c *Client) WriteWords(area byte, address uint16, words []uint16) error {
	data := make([]byte, len(words)*2)
	for i, w := range words {
		binary.BigEndian.PutUint16(data[i*2:i*2+2], w)
	}
	payload := buildMemAreaPayload(cmdMemoryAreaWrite, area, address, 0, uint16(len(words)), data)
	_, err := c.exchange(payload)
	return err
}

// WriteBits 写位区，每个位占 1 字节(0x00/0x01)
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

// buildMemAreaPayload 构造内存区读/写命令载荷：MRC SRC + 区码(1) + 字地址(2) + 位偏移(1) + 数量(2) [+ 数据]
func buildMemAreaPayload(cmd uint16, area byte, address uint16, bitOffset byte, count uint16, data []byte) []byte {
	payload := make([]byte, 8, 8+len(data))
	binary.BigEndian.PutUint16(payload[0:2], cmd)
	payload[2] = area
	binary.BigEndian.PutUint16(payload[3:5], address)
	payload[5] = bitOffset
	binary.BigEndian.PutUint16(payload[6:8], count)
	return append(payload, data...)
}

// buildFrame 构造 FINS 帧：ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID + 命令载荷
func (c *Client) buildFrame(sid byte, payload []byte) []byte {
	frame := make([]byte, 10, 10+len(payload))
	frame[0] = 0x80 // 命令帧，要求响应
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

// exchange 发送一帧并等待同 SID 响应，返回响应数据段(MRC SRC MRES SRES 之后)。
// UDP 读单包；TCP 先读 16 字节帧头按长度读载荷。非本 SID 的响应丢弃重读。
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
		// 丢弃非响应帧：过短帧(FINS/TCP 心跳/空载荷)与 SID 不匹配的帧
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

// readFrame 读一个 FINS 帧(UDP 为单包；TCP 解 16 字节帧头取载荷)
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
	// 非帧发送命令(如节点地址回声)不在此处理，由握手阶段消费
	return payload, nil
}

// wrapTCPFrame 封装 FINS/TCP 帧头："FINS" + 长度(4) + 命令(4) + 错误码(4) + 载荷
func wrapTCPFrame(command uint32, payload []byte) []byte {
	frame := make([]byte, tcpHeaderSize, tcpHeaderSize+len(payload))
	copy(frame[0:4], finsTCPHeader)
	binary.BigEndian.PutUint32(frame[4:8], uint32(8+len(payload)))
	binary.BigEndian.PutUint32(frame[8:12], command)
	binary.BigEndian.PutUint32(frame[12:16], 0)
	return append(frame, payload...)
}

// tcpHandshake FINS/TCP 节点地址协商：发送本端地址，对端回其地址+分配给本端的地址。
// 协商结果写入 dst.Node(DA1) 与 src.Node(SA1)。
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
		c.dst.Node = payload[3] // 对端节点号
	}
	if len(payload) >= 8 && payload[7] != 0 {
		c.src.Node = payload[7] // 对端分配的本端节点号
	}
	return nil
}
