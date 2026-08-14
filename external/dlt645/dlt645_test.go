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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// assertFloat asserts got is float64 and approximately equals want.
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

// --- codec pure function tests ---

// TestChecksum arithmetic sum low 8 bits (manually calculated).
func TestChecksum(t *testing.T) {
	// 68 01 00 00 00 00 00 68 11 04 33 33 34 33 → 0x1B3 → 0xB3
	frame := []byte{0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x11, 0x04, 0x33, 0x33, 0x34, 0x33}
	assert.Equal(t, byte(0xB3), Checksum(frame))
	assert.Equal(t, byte(0), Checksum(nil))
}

// TestBCD encode/decode round-trip with zero padding.
func TestBCD(t *testing.T) {
	// High-order digit in high byte
	assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78}, EncodeBCD(12345678, 4))
	assert.Equal(t, []byte{0x00, 0x00, 0x22, 0x05}, EncodeBCD(2205, 4)) // Pad high with zeros
	assert.Equal(t, []byte{0x00}, EncodeBCD(0, 1))

	assert.Equal(t, uint64(12345678), DecodeBCD([]byte{0x12, 0x34, 0x56, 0x78}))
	assert.Equal(t, uint64(2205), DecodeBCD([]byte{0x00, 0x00, 0x22, 0x05}))
	assert.Equal(t, uint64(0), DecodeBCD([]byte{0x00, 0x00}))
	assert.Equal(t, uint64(99), DecodeBCD([]byte{0x99}))

	// Round-trip
	for _, v := range []uint64{0, 1, 99, 100, 9999, 12345678, 999999999999} {
		assert.Equal(t, v, DecodeBCD(EncodeBCD(v, 6)))
	}
}

// TestParseAddr meter address parsing (12-bit BCD, little-endian).
func TestParseAddr(t *testing.T) {
	a, err := ParseAddr("000000000001")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, a)

	a, err = ParseAddr("123456789012")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x12, 0x90, 0x78, 0x56, 0x34, 0x12}, a)

	// Pad left with zeros if less than 12 bits
	a, err = ParseAddr("1234")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x34, 0x12, 0x00, 0x00, 0x00, 0x00}, a)

	// Odd-length address: left-pad one 0 so the leading digit is parsed, not dropped.
	a, err = ParseAddr("123")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x23, 0x01, 0x00, 0x00, 0x00, 0x00}, a)

	a, err = ParseAddr("1")
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, a)

	// Format round-trip
	assert.Equal(t, "123456789012", FormatAddr([]byte{0x12, 0x90, 0x78, 0x56, 0x34, 0x12}))

	// Invalid
	for _, bad := range []string{"", "0000000000001", "12345678901A", "abcdef"} {
		_, err := ParseAddr(bad)
		assert.NotNil(t, err, "addr %q should be invalid", bad)
	}
}

// TestParseDI data identifier parsing (standard order → wire little-endian).
func TestParseDI(t *testing.T) {
	// 02-01-01-00 = DI3 DI2 DI1 DI0 → wire order DI0..DI3
	di, err := ParseDI("02-01-01-00")
	assert.Nil(t, err)
	assert.Equal(t, [4]byte{0x00, 0x01, 0x01, 0x02}, di)

	di, err = ParseDI("00-01-00-00")
	assert.Nil(t, err)
	assert.Equal(t, [4]byte{0x00, 0x00, 0x01, 0x00}, di)

	// Continuous format equivalent
	di2, err := ParseDI("02010100")
	assert.Nil(t, err)
	assert.Equal(t, [4]byte{0x00, 0x01, 0x01, 0x02}, di2)

	// Format round-trip
	assert.Equal(t, "00-01-00-00", FormatDI(di))
	assert.Equal(t, "02-01-01-00", FormatDI(di2))

	// Invalid
	for _, bad := range []string{"", "02-01-01", "02-01-01-00-00", "zz-01-01-00", "010203"} {
		_, err := ParseDI(bad)
		assert.NotNil(t, err, "DI %q should be invalid", bad)
	}
}

// TestBuildReadFrame read request frame byte-by-byte assertion (including 0x33, CS, frame tail).
func TestBuildReadFrame(t *testing.T) {
	// Address 000000000001, DI 00-01-00-00 (total forward active energy)
	di, _ := ParseDI("00-01-00-00")
	frame, err := BuildReadFrame("000000000001", di[:])
	assert.Nil(t, err)
	assert.Equal(t, []byte{
		0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, // Frame header + address + 0x68
		0x11, 0x04, // Control code read data + length 4
		0x33, 0x33, 0x34, 0x33, // DI plus 0x33
		0xB3, // CS (manually calculated)
		0x16, // Frame tail
	}, frame)

	// Address 123456789012, DI 02-01-01-00 (Phase A voltage)
	di, _ = ParseDI("02-01-01-00")
	frame, err = BuildReadFrame("123456789012", di[:])
	assert.Nil(t, err)
	assert.Equal(t, []byte{
		0x68, 0x12, 0x90, 0x78, 0x56, 0x34, 0x12, 0x68,
		0x11, 0x04,
		0x33, 0x34, 0x34, 0x35,
		0x6B, // CS (manually calculated)
		0x16,
	}, frame)

	// Invalid DI length
	_, err = BuildReadFrame("000000000001", []byte{0x00, 0x01})
	assert.NotNil(t, err)
	// Invalid address
	_, err = BuildReadFrame("xyz", di[:])
	assert.NotNil(t, err)
}

// TestBuildWriteFrame write request frame: data field = DI + data, both plus 0x33.
func TestBuildWriteFrame(t *testing.T) {
	di, _ := ParseDI("00-01-00-00")
	// Write data [0x00,0x01] (BCD wire order for 100.00 kWh)
	frame, err := BuildWriteFrame("000000000001", di[:], []byte{0x00, 0x01})
	assert.Nil(t, err)

	ctrl, _, payload, perr := parseFrame(frame)
	assert.Nil(t, perr)
	assert.Equal(t, byte(ctrlWrite), ctrl)
	// payload = DI + data (minus 0x33 restored)
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}, payload)
}

// buildTestResponse constructs response frame (test helper).
func buildTestResponse(addr string, ctrl byte, payload []byte) []byte {
	addrBytes, _ := ParseAddr(addr)
	return buildFrame(addrBytes, ctrl, payload)
}

// TestParseResponse normal/error/corrupted frame parsing.
func TestParseResponse(t *testing.T) {
	// Normal response: DI(00-01-00-00) + energy data 123456.78 kWh
	resp := buildTestResponse("000000000001", ctrlRead|respMask,
		[]byte{0x00, 0x00, 0x01, 0x00, 0x78, 0x56, 0x34, 0x12})
	// Byte-by-byte assertion (0x33 transform + CS manual value)
	assert.Equal(t, []byte{
		0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68,
		0x91, 0x08,
		0x33, 0x33, 0x34, 0x33, 0xAB, 0x89, 0x67, 0x45,
		0x17, // CS (manually calculated)
		0x16,
	}, resp)
	di, data, err := ParseResponse(resp)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x00}, di)
	assert.Equal(t, []byte{0x78, 0x56, 0x34, 0x12}, data)

	// Error response: ERR=0x03 no data (control code 0x11|0xC0=0xD1)
	resp = buildTestResponse("000000000001", ctrlRead|respMask|errMask, []byte{0x03})
	assert.Equal(t, []byte{
		0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68,
		0xD1, 0x01, 0x36,
		0xD9, // CS (manually calculated)
		0x16,
	}, resp)
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "no data"), err)

	// Checksum error
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00, 0x00})
	resp[len(resp)-2]++ // Tamper CS
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "checksum"), err)

	// Tamper data field causes checksum failure
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00, 0x00})
	resp[10]++
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)

	// Frame too short
	_, _, err = ParseResponse([]byte{0x68, 0x00})
	assert.NotNil(t, err)

	// Length field mismatch
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00})
	_, _, err = ParseResponse(resp[:len(resp)-1])
	assert.NotNil(t, err)

	// Frame tail error
	resp = buildTestResponse("000000000001", ctrlRead|respMask, []byte{0x00, 0x00, 0x01, 0x00})
	resp[len(resp)-1] = 0x00
	_, _, err = ParseResponse(resp)
	assert.NotNil(t, err)

	// Non-slave response frame (master request frame)
	diBytes, _ := ParseDI("00-01-00-00")
	req, _ := BuildReadFrame("000000000001", diBytes[:])
	_, _, err = ParseResponse(req)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "not a slave response"), err)
}

// --- value decode tests ---

// TestDecodeValue decode various data by DI standard/Type.
func TestDecodeValue(t *testing.T) {
	cases := []struct {
		name string
		di   string
		raw  []byte
		pt   iot_points.Point
		want interface{}
	}{
		// Total forward active energy: BCD 4 bytes 2 decimals, 123456.78 kWh
		{"energy", "00-01-00-00", []byte{0x78, 0x56, 0x34, 0x12}, iot_points.Point{}, 123456.78},
		// Phase A voltage: BCD 3 bytes 1 decimal, 220.5 V
		{"voltage", "02-01-01-00", []byte{0x05, 0x22, 0x00}, iot_points.Point{}, 220.5},
		// Phase A current: BCD 3 bytes 3 decimals signed, 1.500 A
		{"current_pos", "02-02-01-00", []byte{0x00, 0x15, 0x00}, iot_points.Point{}, 1.5},
		// Phase A current negative: highest byte bit7 set, -1.500 A
		{"current_neg", "02-02-01-00", []byte{0x00, 0x15, 0x80}, iot_points.Point{}, -1.5},
		// Instantaneous total active power negative: -5.1234 kW
		{"power_neg", "02-03-00-00", []byte{0x34, 0x12, 0x85}, iot_points.Point{}, -5.1234},
		// Unknown DI: unsigned BCD integer
		{"unknown_di", "05-06-00-00", []byte{0x21, 0x43}, iot_points.Point{}, uint64(4321)},
		// Type BCD + Scale: raw BCD integer × scale
		{"bcd_scale", "05-06-00-00", []byte{0x78, 0x56, 0x34, 0x12}, iot_points.Point{Type: "BCD", Scale: 0.01}, 123456.78},
		// Energy + Scale/Offset engineering conversion: 100.00 kWh → 201.0
		{"scale_offset", "00-01-00-00", []byte{0x00, 0x00, 0x01, 0x00}, iot_points.Point{Scale: 2, Offset: 1}, 201.0},
		// Binary little-endian UINT16
		{"UINT16", "05-06-00-00", []byte{0x39, 0x05}, iot_points.Point{Type: iot_points.TypeUint16}, 1337.0},
		// Binary little-endian INT16 negative
		{"int16_neg", "05-06-00-00", []byte{0xFF, 0xFF}, iot_points.Point{Type: iot_points.TypeInt16}, -1.0},
		// Binary little-endian INT32 minimum
		{"int32_min", "05-06-00-00", []byte{0x00, 0x00, 0x00, 0x80}, iot_points.Point{Type: iot_points.TypeInt32}, -2147483648.0},
		// Binary little-endian INT64 negative
		{"int64_neg", "05-06-00-00", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, iot_points.Point{Type: iot_points.TypeInt64}, -1.0},
		// Binary little-endian UINT32
		{"UINT32", "05-06-00-00", []byte{0x40, 0xE2, 0x01, 0x00}, iot_points.Point{Type: iot_points.TypeUint32}, 123456.0},
		// BOOL
		{"bool_true", "05-06-00-00", []byte{0x01}, iot_points.Point{Type: iot_points.TypeBool}, true},
		{"bool_false", "05-06-00-00", []byte{0x00}, iot_points.Point{Type: iot_points.TypeBool}, false},
		// STRING
		{"string_val", "05-06-00-00", []byte("AB"), iot_points.Point{Type: iot_points.TypeString}, "AB"},
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

	// Unsupported type
	di, _ := ParseDI("00-01-00-00")
	_, err := decodeValue(di, []byte{0x00}, iot_points.Point{Type: "FLOAT32"})
	assert.NotNil(t, err)
	// Binary data too short
	_, err = decodeValue(di, []byte{0x01}, iot_points.Point{Type: iot_points.TypeUint32})
	assert.NotNil(t, err)
}

// TestEncodeWriteValue write value BCD encoding (known DI decimals + Type bytes + sign).
func TestEncodeWriteValue(t *testing.T) {
	// Power DI 4 decimals + UINT32 → 4 bytes wire BCD: 1.2345 → {0x45,0x23,0x01,0x00}
	b, err := encodeWriteValue(iot_points.Point{Addr: "02-03-00-00", Type: iot_points.TypeUint32, Value: "1.2345"})
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x45, 0x23, 0x01, 0x00}, b)

	// Energy DI 2 decimals + no Type → natural 3 bytes: 100.00 → BCD 10000(5-digit) → {0x00,0x00,0x01}
	b, err = encodeWriteValue(iot_points.Point{Addr: "00-01-00-00", Value: "100.00"})
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x01}, b)

	// Negative power: highest byte sign bit set -1.500 → 1500 → {0x00,0x15} → {0x00,0x95}
	b, err = encodeWriteValue(iot_points.Point{Addr: "02-02-01-00", Value: "-1.5"})
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x00, 0x95}, b)

	// Invalid value
	_, err = encodeWriteValue(iot_points.Point{Addr: "00-01-00-00", Value: "abc"})
	assert.NotNil(t, err)
}

// --- mock meter + end-to-end tests ---

// mockMeter simulates DLT645 meter: receive read frame lookup preset data return response, receive write frame store and respond.
type mockMeter struct {
	t    *testing.T
	ln   net.Listener
	addr string
	mu   sync.Mutex
	data map[[diLen]byte][]byte // DI (wire order) → response data (raw bytes, no 0x33)
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

// set preset DI response data (wire order raw bytes).
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
				m.reply(conn, ctrlRead|respMask|errMask, []byte{0x03}) // No data
			}
		case ctrlWrite:
			m.mu.Lock()
			m.data[di] = append([]byte(nil), payload[diLen:]...)
			m.mu.Unlock()
			m.reply(conn, ctrlWrite|respMask, di[:]) // Write response data field is DI
		}
	}
}

// reply constructs and sends response frame (payload is data without 0x33).
func (m *mockMeter) reply(conn net.Conn, ctrl byte, payload []byte) {
	addrBytes, err := ParseAddr(m.addr)
	if err != nil {
		return
	}
	_, _ = conn.Write(buildFrame(addrBytes, ctrl, payload))
}

// newTestDriver connects to mock meter and returns driver (auto cleanup on test end).
func newTestDriver(t *testing.T, m *mockMeter) *driver {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", m.port()))
	assert.Nil(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return newDriver(conn, m.addr, 2*time.Second)
}

// TestDriver_ReadPoints end-to-end: preset 4 data types, read values decoded by DI standard.
func TestDriver_ReadPoints(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	m.set("00-01-00-00", []byte{0x78, 0x56, 0x34, 0x12}) // 123456.78 kWh
	m.set("02-01-01-00", []byte{0x05, 0x22, 0x00})       // 220.5 V
	m.set("02-02-01-00", []byte{0x00, 0x15, 0x80})       // -1.500 A
	m.set("02-03-00-00", []byte{0x34, 0x12, 0x05})       // 5.1234 kW

	d := newTestDriver(t, m)
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "total_active_energy", Addr: "00-01-00-00"},
		{Name: "voltage_a", Addr: "02-01-01-00"},
		{Name: "current_a", Addr: "02-02-01-00"},
		{Name: "instantaneous_active_power", Addr: "02-03-00-00"},
	})
	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, "total_active_energy", data[0].Name)
	assertFloat(t, 123456.78, data[0].Value)
	assertFloat(t, 220.5, data[1].Value)
	assertFloat(t, -1.5, data[2].Value)
	assertFloat(t, 5.1234, data[3].Value)
	assert.True(t, data[0].Timestamp > 0)
}

// TestDriver_ReadNoData meter has no data item → error response ERR=0x03.
func TestDriver_ReadNoData(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	d := newTestDriver(t, m)
	_, err := d.ReadPoints([]iot_points.Point{{Name: "x", Addr: "00-01-00-00"}})
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "no data"), err)
}

// TestDriver_ReadInvalidAddr invalid DI → parse error.
func TestDriver_ReadInvalidAddr(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	d := newTestDriver(t, m)
	_, err := d.ReadPoints([]iot_points.Point{{Name: "x", Addr: "bad-di"}})
	assert.NotNil(t, err)
}

// TestDriver_Scale end-to-end engineering conversion.
func TestDriver_Scale(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	m.set("05-06-00-00", []byte{0x00, 0x01}) // Raw BCD 100 (wire order little-endian)

	d := newTestDriver(t, m)
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "raw", Addr: "05-06-00-00", Type: "BCD", Scale: 0.1, Offset: 5},
	})
	assert.Nil(t, err)
	assertFloat(t, 15.0, data[0].Value) // 100*0.1+5
}

// TestDriver_WriteThenRead end-to-end: write stored by mock, then read to verify.
func TestDriver_WriteThenRead(t *testing.T) {
	m := newMockMeter(t, "000000000001")
	d := newTestDriver(t, m)

	// Write power 1.2345kW (UINT32, 4 decimals)
	err := d.WritePoints([]iot_points.Point{
		{Name: "power", Addr: "02-03-00-00", Type: iot_points.TypeUint32, Value: "1.2345"},
	})
	assert.Nil(t, err)
	// Read back
	data, err := d.ReadPoints([]iot_points.Point{{Name: "power", Addr: "02-03-00-00"}})
	assert.Nil(t, err)
	assertFloat(t, 1.2345, data[0].Value)

	// Write energy 100.00 kWh (no Type, 2 decimals natural length)
	err = d.WritePoints([]iot_points.Point{
		{Name: "energy", Addr: "00-01-00-00", Value: "100.00"},
	})
	assert.Nil(t, err)
	data, err = d.ReadPoints([]iot_points.Point{{Name: "energy", Addr: "00-01-00-00"}})
	assert.Nil(t, err)
	assertFloat(t, 100.0, data[0].Value)
}

// --- node-level tests ---

// TestReadNodeNodes node type and default config
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

// TestReadNode_E2E node-level end-to-end: config points, Success chain outputs Data list.
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
			{"name": "total_active_energy", "addr": "00-01-00-00"},
			{"name": "voltage_a", "addr": "02-01-01-00"},
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
		assert.Equal(t, "total_active_energy", datas[0].Name)
		assertFloat(t, 123456.78, datas[0].Value)
		assertFloat(t, 220.5, datas[1].Value)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for dlt645 read callback")
	}
}

// TestReadNode_MsgDataPoints dual entry: msg.Data points override config, support ${metadata.xx} template.
func TestReadNode_MsgDataPoints(t *testing.T) {
	m := newMockMeter(t, "000000000002")
	m.set("02-03-00-00", []byte{0x34, 0x12, 0x85}) // -5.1234 kW

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/dlt645Read", types.Configuration{
		"server":  fmt.Sprintf("tcp://127.0.0.1:%d", m.port()),
		"addr":    "000000000002",
		"timeout": 2,
		// Config points overridden by msg.Data
		"points": []map[string]interface{}{
			{"name": "not_read", "addr": "00-01-00-00"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan string, 1)
	var got string
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		MetaData: types.BuildMetadata(map[string]string{"di": "02-03-00-00"}),
		Data:     `[{"name":"instantaneous_active_power","addr":"${metadata.di}"}]`,
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
		assert.Equal(t, "instantaneous_active_power", datas[0].Name)
		assertFloat(t, -5.1234, datas[0].Value)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for dlt645 read callback")
	}
}

// TestReadNode_NoServer no meter connection failure, node goes to Failure chain.
func TestReadNode_NoServer(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/dlt645Read", types.Configuration{
		"server":  "tcp://127.0.0.1:19998",
		"addr":    "000000000001",
		"timeout": 1,
		"points": []map[string]interface{}{
			{"name": "energy", "addr": "00-01-00-00"},
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

// timeoutConn swallows writes and fails every read with a deadline error,
// simulating a silent meter.
type timeoutConn struct {
	writes int
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
}
func (c *timeoutConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}
func (c *timeoutConn) Close() error                       { return nil }
func (c *timeoutConn) LocalAddr() net.Addr                { return nil }
func (c *timeoutConn) RemoteAddr() net.Addr               { return nil }
func (c *timeoutConn) SetDeadline(t time.Time) error      { return nil }
func (c *timeoutConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *timeoutConn) SetWriteDeadline(t time.Time) error { return nil }

// TestReadPoints_TimeoutStopsReading: 第一个点位读超时后整表判失败,
// 不再对后续点位各等一个超时窗口。
func TestReadPoints_TimeoutStopsReading(t *testing.T) {
	conn := &timeoutConn{}
	d := newDriver(conn, "000000000001", 100*time.Millisecond)
	pts := []iot_points.Point{
		{Name: "energy", Addr: "00-01-00-00"},
		{Name: "ua", Addr: "02-01-01-00"},
		{Name: "ia", Addr: "02-02-01-00"},
	}
	got, err := d.ReadPoints(pts)

	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "all 3 dlt645 points failed"))
	assert.Equal(t, 1, conn.writes, "超时后不应继续读后续点位")
	_ = got
}
