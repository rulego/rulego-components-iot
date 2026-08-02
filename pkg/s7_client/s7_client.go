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

// Package s7client wraps robinson/gos7, providing Siemens S7 PLC connections,
// bulk point read/write, and type parsing. Outputs unified Data contract for downstream rulego nodes.
//
// Only supports classic S7comm (PG/OP communication for S7-200SMART/300/400/1200/1500).
// Prerequisite: TIA Portal must enable "Allow PUT/GET communication" and disable "Optimized Block Access".

package s7client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/robinson/gos7"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// S7DataMsgType is the S7 data message type.
const S7DataMsgType = "S7_DATA"

// S7 area IDs (gos7 internal lowercase unexported, redefined by protocol constant values)
const (
	areaDB = 0x84 // Data Block
	areaM  = 0x83 // Markers
	areaI  = 0x81 // Inputs
	areaQ  = 0x82 // Outputs
)

// Data is the unified point output contract.
type Data struct {
	Name      string      `json:"name"`
	Address   string      `json:"address"`
	Value     interface{} `json:"value"`
	Type      string      `json:"type"`
	Quality   string      `json:"quality"`
	Timestamp time.Time   `json:"timestamp"`
}

// Point S7 point definition, shared for read/write
type Point struct {
	Name      string `json:"name"`                // Point name (included in output for downstream access)
	Area      string `json:"area"`                // DB/M/I/Q
	DbNumber  int    `json:"dbNumber"`            // Valid only when area=DB
	Address   int    `json:"address"`             // Byte offset
	Type      string `json:"type"`                // BOOL/BYTE/INT/WORD/DINT/DWORD/REAL/LREAL/STRING
	BitOffset int    `json:"bitOffset,omitempty"` // Valid only for type=BOOL, 0-7
	Count     int    `json:"count,omitempty"`     // Count, default 1; ignored for STRING
	StringLen int    `json:"stringLen,omitempty"` // STRING declared max length, default 254
	Value     string `json:"value,omitempty"`     // Write only: string representation of value
}

// ConfigProp S7 connection configuration interface
type ConfigProp interface {
	GetServer() string // host:port
	GetRack() int
	GetSlot() int
	GetTimeout() int // seconds
}

// Holder S7 client configuration holder
type Holder struct {
	Config ConfigProp
}

// DefaultHolder default configuration
func DefaultHolder(c ConfigProp) *Holder {
	return &Holder{Config: c}
}

// NewHandler creates and connects S7 TCP handler (connection holder, reused by SharedNode)
func (h *Holder) NewHandler() (*gos7.TCPClientHandler, error) {
	if h.Config == nil {
		return nil, errors.New("s7 config is nil")
	}
	timeout := h.Config.GetTimeout()
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	host, port, err := iot_points.ParseServer(h.Config.GetServer(), 102)
	if err != nil {
		return nil, err
	}
	handler := gos7.NewTCPClientHandler(net.JoinHostPort(host, strconv.Itoa(port)), h.Config.GetRack(), h.Config.GetSlot())
	handler.Timeout = time.Duration(timeout) * time.Second
	handler.IdleTimeout = time.Duration(timeout) * time.Second
	if err := handler.Connect(); err != nil {
		return nil, err
	}
	return handler, nil
}

// parseArea area string -> area ID
func parseArea(area string) (int, error) {
	switch strings.ToUpper(strings.TrimSpace(area)) {
	case "DB":
		return areaDB, nil
	case "M":
		return areaM, nil
	case "I":
		return areaI, nil
	case "Q":
		return areaQ, nil
	}
	return 0, fmt.Errorf("unsupported s7 area: %q (supported: DB/M/I/Q)", area)
}

// sizeOfType byte count of a single value
func sizeOfType(t string) int {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "BOOL", "BYTE":
		return 1
	case "INT", "WORD":
		return 2
	case "DINT", "DWORD", "REAL":
		return 4
	case "LREAL":
		return 8
	case "STRING":
		return 256
	}
	return 0
}

// stringMaxLen declared max length of STRING point, defaults to 254 if not declared (<=0)
func stringMaxLen(p Point) int {
	if p.StringLen > 0 {
		return p.StringLen
	}
	return 254
}

// formatAddr generates readable address string
func formatAddr(p Point) string {
	area := strings.ToUpper(strings.TrimSpace(p.Area))
	if area == "DB" {
		base := fmt.Sprintf("DB%d.%d", p.DbNumber, p.Address)
		if strings.ToUpper(p.Type) == "BOOL" {
			return fmt.Sprintf("%s.%d", base, p.BitOffset)
		}
		return base
	}
	if strings.ToUpper(p.Type) == "BOOL" {
		return fmt.Sprintf("%s%d.%d", area, p.Address, p.BitOffset)
	}
	return fmt.Sprintf("%s%d", area, p.Address)
}

// ReadPoints batch reads points. Single point failure does not affect others (marked quality=bad)
func ReadPoints(handler *gos7.TCPClientHandler, points []Point, logger types.Logger) ([]Data, error) {
	if handler == nil {
		return nil, errors.New("s7 handler is nil")
	}
	client := gos7.NewClient(handler)
	results := make([]Data, 0, len(points))
	failCount := 0
	var lastErr error
	for _, p := range points {
		d := Data{
			Name:      p.Name,
			Address:   formatAddr(p),
			Type:      strings.ToUpper(strings.TrimSpace(p.Type)),
			Timestamp: time.Now(),
		}
		val, err := readPoint(client, p)
		if err != nil {
			d.Quality = "bad"
			failCount++
			lastErr = err
			if logger != nil {
				logger.Errorf("[S7] read %s error: %v", d.Address, err)
			}
		} else {
			d.Quality = "good"
			d.Value = val
		}
		results = append(results, d)
	}
	// All points failed: suspected connection-level error, return error
	if len(points) > 0 && failCount == len(points) {
		return results, fmt.Errorf("all %d points failed (possible connection error): %w", failCount, lastErr)
	}
	return results, nil
}

// readPoint reads a single point
func readPoint(client gos7.Client, p Point) (interface{}, error) {
	area, err := parseArea(p.Area)
	if err != nil {
		return nil, err
	}
	t := strings.ToUpper(strings.TrimSpace(p.Type))
	ts := sizeOfType(t)
	if ts == 0 {
		return nil, fmt.Errorf("unsupported s7 type: %q", p.Type)
	}
	count := p.Count
	if count <= 0 {
		count = 1
	}
	sizeBytes := ts
	if t == "STRING" {
		sizeBytes = stringMaxLen(p) + 2
	} else {
		sizeBytes = ts * count
	}
	buf := make([]byte, sizeBytes)

	switch area {
	case areaDB:
		err = client.AGReadDB(p.DbNumber, p.Address, sizeBytes, buf)
	case areaM:
		err = client.AGReadMB(p.Address, sizeBytes, buf)
	case areaI:
		err = client.AGReadEB(p.Address, sizeBytes, buf)
	case areaQ:
		err = client.AGReadAB(p.Address, sizeBytes, buf)
	}
	if err != nil {
		return nil, err
	}
	if count > 1 && t != "BOOL" && t != "STRING" {
		return decodeArray(buf, t, count)
	}
	return decodeScalar(buf, t, p.BitOffset)
}

// decodeScalar parses a single value (big-endian, S7 default byte order)
func decodeScalar(buf []byte, t string, bitOffset int) (interface{}, error) {
	switch t {
	case "BOOL":
		off := bitOffset
		if off < 0 || off > 7 {
			off = 0
		}
		if len(buf) < 1 {
			return false, nil
		}
		return (buf[0]>>uint(off))&1 == 1, nil
	case "BYTE":
		if len(buf) < 1 {
			return byte(0), nil
		}
		return buf[0], nil
	case "INT":
		if len(buf) < 2 {
			return int16(0), nil
		}
		return int16(binary.BigEndian.Uint16(buf)), nil
	case "WORD":
		if len(buf) < 2 {
			return uint16(0), nil
		}
		return binary.BigEndian.Uint16(buf), nil
	case "DINT":
		if len(buf) < 4 {
			return int32(0), nil
		}
		return int32(binary.BigEndian.Uint32(buf)), nil
	case "DWORD":
		if len(buf) < 4 {
			return uint32(0), nil
		}
		return binary.BigEndian.Uint32(buf), nil
	case "REAL":
		if len(buf) < 4 {
			return float32(0), nil
		}
		return math.Float32frombits(binary.BigEndian.Uint32(buf)), nil
	case "LREAL":
		if len(buf) < 8 {
			return float64(0), nil
		}
		return math.Float64frombits(binary.BigEndian.Uint64(buf)), nil
	case "STRING":
		// S7 string: buf[0]=maxLen, buf[1]=actualLen, buf[2:2+actualLen]=chars
		if len(buf) < 2 {
			return "", nil
		}
		actual := int(buf[1])
		if 2+actual > len(buf) {
			actual = len(buf) - 2
		}
		if actual < 0 {
			actual = 0
		}
		return string(buf[2 : 2+actual]), nil
	}
	return nil, fmt.Errorf("unsupported type: %s", t)
}

// decodeArray parses array (count values of same type)
func decodeArray(buf []byte, t string, count int) (interface{}, error) {
	ts := sizeOfType(t)
	arr := make([]interface{}, 0, count)
	for i := 0; i < count; i++ {
		end := (i + 1) * ts
		if end > len(buf) {
			break
		}
		v, err := decodeScalar(buf[i*ts:end], t, 0)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
	return arr, nil
}

// WritePoints batch writes points. Returns error immediately on any point failure
func WritePoints(handler *gos7.TCPClientHandler, points []Point) error {
	if handler == nil {
		return errors.New("s7 handler is nil")
	}
	client := gos7.NewClient(handler)
	for _, p := range points {
		if err := writePoint(client, p); err != nil {
			return fmt.Errorf("write %s error: %w", formatAddr(p), err)
		}
	}
	return nil
}

func writePoint(client gos7.Client, p Point) error {
	area, err := parseArea(p.Area)
	if err != nil {
		return err
	}
	t := strings.ToUpper(strings.TrimSpace(p.Type))
	if t == "BOOL" {
		return writeBit(client, area, p)
	}
	buf, err := encodeScalar(p.Value, t, p.StringLen)
	if err != nil {
		return err
	}
	switch area {
	case areaDB:
		return client.AGWriteDB(p.DbNumber, p.Address, len(buf), buf)
	case areaM:
		return client.AGWriteMB(p.Address, len(buf), buf)
	case areaI:
		return client.AGWriteEB(p.Address, len(buf), buf)
	case areaQ:
		return client.AGWriteAB(p.Address, len(buf), buf)
	}
	return fmt.Errorf("unsupported area: %s", p.Area)
}

// writeBit bit write: read-modify-write
func writeBit(client gos7.Client, area int, p Point) error {
	buf := make([]byte, 1)
	switch area {
	case areaDB:
		if err := client.AGReadDB(p.DbNumber, p.Address, 1, buf); err != nil {
			return err
		}
	case areaM:
		if err := client.AGReadMB(p.Address, 1, buf); err != nil {
			return err
		}
	case areaI:
		if err := client.AGReadEB(p.Address, 1, buf); err != nil {
			return err
		}
	case areaQ:
		if err := client.AGReadAB(p.Address, 1, buf); err != nil {
			return err
		}
	default:
		return fmt.Errorf("bit write unsupported for area: %s", p.Area)
	}
	b, err := parseBoolValue(p.Value)
	if err != nil {
		return err
	}
	off := uint(p.BitOffset)
	if off > 7 {
		off = 0
	}
	if b {
		buf[0] |= 1 << off
	} else {
		buf[0] &^= 1 << off
	}
	switch area {
	case areaDB:
		return client.AGWriteDB(p.DbNumber, p.Address, 1, buf)
	case areaM:
		return client.AGWriteMB(p.Address, 1, buf)
	case areaI:
		return client.AGWriteEB(p.Address, 1, buf)
	case areaQ:
		return client.AGWriteAB(p.Address, 1, buf)
	}
	return nil
}

// parseBoolValue parses bool value string (supports true/false/0/1)
func parseBoolValue(s string) (bool, error) {
	s = strings.TrimSpace(s)
	if b, err := strconv.ParseBool(s); err == nil {
		return b, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n != 0, nil
	}
	return false, fmt.Errorf("invalid bool value: %q", s)
}

// encodeScalar encodes value string to bytes (big-endian, S7 default)
func encodeScalar(value string, t string, stringLen int) ([]byte, error) {
	v := strings.TrimSpace(value)
	switch t {
	case "BYTE":
		n, err := strconv.ParseUint(v, 0, 8)
		if err != nil {
			return nil, err
		}
		return []byte{byte(n)}, nil
	case "INT":
		n, err := strconv.ParseInt(v, 0, 16)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(n))
		return buf, nil
	case "WORD":
		n, err := strconv.ParseUint(v, 0, 16)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(n))
		return buf, nil
	case "DINT":
		n, err := strconv.ParseInt(v, 0, 32)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(n))
		return buf, nil
	case "DWORD":
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(n))
		return buf, nil
	case "REAL":
		n, err := strconv.ParseFloat(v, 32)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, math.Float32bits(float32(n)))
		return buf, nil
	case "LREAL":
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, math.Float64bits(n))
		return buf, nil
	case "STRING":
		maxLen := stringLen
		if maxLen <= 0 {
			maxLen = 254
		}
		content := []byte(v)
		if len(content) > maxLen {
			content = content[:maxLen]
		}
		buf := make([]byte, maxLen+2)
		buf[0] = byte(maxLen)
		buf[1] = byte(len(content))
		copy(buf[2:], content)
		return buf, nil
	}
	return nil, fmt.Errorf("unsupported type for encode: %s", t)
}
