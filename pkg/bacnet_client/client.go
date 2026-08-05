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

package bacnetclient

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
)

const (
	defaultPort    = 47808 // BACnet/IP default UDP port
	defaultTimeout = 5 * time.Second
	readBufSize    = 2048
)

// Client is a BACnet/IP acquisition client. Concurrent-safe: a mutex serializes request/response exchanges.
type Client struct {
	conn     net.Conn
	timeout  time.Duration
	invokeID uint32 // atomic
	mu       sync.Mutex
	readBuf  [readBufSize]byte
	closed   atomic.Bool
}

// NewClient creates and connects a BACnet/IP client (UDP) to server (host or host:port; default port 47808).
func NewClient(server string, timeout time.Duration) (*Client, error) {
	host, port, err := iot_points.ParseServer(server, defaultPort)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("bacnet resolve %s: %w", server, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("bacnet dial %s: %w", server, err)
	}
	return &Client{conn: conn, timeout: timeout}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) nextInvokeID() uint8 {
	for {
		id := uint8(atomic.AddUint32(&c.invokeID, 1))
		if id != 0 {
			return id
		}
	}
}

// send writes a request frame and reads the response with a matching invokeID, discarding others.
func (c *Client) send(req []byte, invokeID uint8) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return nil, errors.New("bacnet client closed")
	}
	deadline := time.Now().Add(c.timeout)
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(req); err != nil {
		return nil, fmt.Errorf("bacnet write: %w", err)
	}
	for {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		n, err := c.conn.Read(c.readBuf[:])
		if err != nil {
			return nil, fmt.Errorf("bacnet read: %w", err)
		}
		info, perr := parseResponse(c.readBuf[:n])
		if perr != nil || info.invokeID != invokeID {
			continue
		}
		out := make([]byte, n)
		copy(out, c.readBuf[:n])
		return out, nil
	}
}

// ReadProperty reads a single object property and returns the decoded value.
func (c *Client) ReadProperty(objType uint16, instance uint32, property uint32) (interface{}, error) {
	id := c.nextInvokeID()
	req, err := readPropertyRequest(id, objType, instance, property)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(req, id)
	if err != nil {
		return nil, err
	}
	return parseReadPropertyResponse(resp)
}

// ReadPropertyMultiple reads properties of multiple objects in one request (BACnet service 0x0e),
// returning per-object results. Use this for multi-point collection to avoid N round-trips.
// Callers should fall back to ReadProperty if the device rejects this service.
func (c *Client) ReadPropertyMultiple(specs []AccessSpec) ([]ReadAccessResult, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	id := c.nextInvokeID()
	req, err := readPropertyMultipleRequest(id, specs)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(req, id)
	if err != nil {
		return nil, err
	}
	return parseReadPropertyMultipleResponse(resp)
}

// WriteProperty writes a single object property. valueTag selects the BACnet application data type;
// priority 0 omits the priority field (device default).
func (c *Client) WriteProperty(objType uint16, instance uint32, property uint32, valueTag uint8, value interface{}, priority uint8) error {
	id := c.nextInvokeID()
	req, err := writePropertyRequest(id, objType, instance, property, valueTag, value, priority)
	if err != nil {
		return err
	}
	resp, err := c.send(req, id)
	if err != nil {
		return err
	}
	return parseWritePropertyResponse(resp)
}
