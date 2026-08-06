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

package modbus

import (
	"sync"
	"testing"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/simonvetter/modbus"
	"github.com/stretchr/testify/assert"
)

// parseModiconAddr: 4 address types + extended + 1-based->0-based + invalid.
func TestParseModiconAddr(t *testing.T) {
	tests := []struct {
		addr        string
		wantKind    string
		wantProto   uint16
		wantRegType modbus.RegType
	}{
		{"00001", modiconCoil, 0, 0},
		{"00010", modiconCoil, 9, 0},
		{"10001", modiconDI, 0, 0},
		{"10005", modiconDI, 4, 0},
		{"30001", modiconIR, 0, modbus.INPUT_REGISTER},
		{"30010", modiconIR, 9, modbus.INPUT_REGISTER},
		{"40001", modiconHR, 0, modbus.HOLDING_REGISTER},
		{"40010", modiconHR, 9, modbus.HOLDING_REGISTER},
		{"465535", modiconHR, 65534, modbus.HOLDING_REGISTER}, // extended 6 digits
	}
	for _, tt := range tests {
		regType, proto, kind, err := parseModiconAddr(tt.addr)
		assert.Nil(t, err, "addr %s", tt.addr)
		assert.Equal(t, tt.wantKind, kind, "addr %s kind", tt.addr)
		assert.Equal(t, tt.wantProto, proto, "addr %s proto", tt.addr)
		assert.Equal(t, tt.wantRegType, regType, "addr %s regType", tt.addr)
	}

	// invalid
	for _, bad := range []string{"0", "50000", "99999", "abc", ""} {
		_, _, _, err := parseModiconAddr(bad)
		assert.NotNil(t, err, "addr %q should be invalid", bad)
	}
}

// --- integration test: real modbus end-to-end via simonvetter built-in server ---

// testHandler implements modbus.RequestHandler, storing coil/di/hr/ir in memory.
type testHandler struct {
	mu    sync.Mutex
	coils map[uint16]bool
	di    map[uint16]bool
	hr    map[uint16]uint16
	ir    map[uint16]uint16
}

func newTestHandler() *testHandler {
	return &testHandler{
		coils: map[uint16]bool{}, di: map[uint16]bool{},
		hr: map[uint16]uint16{}, ir: map[uint16]uint16{},
	}
}

func (h *testHandler) HandleCoils(req *modbus.CoilsRequest) ([]bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.IsWrite {
		for i, v := range req.Args {
			h.coils[req.Addr+uint16(i)] = v
		}
		return nil, nil
	}
	res := make([]bool, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.coils[req.Addr+i])
	}
	return res, nil
}

func (h *testHandler) HandleDiscreteInputs(req *modbus.DiscreteInputsRequest) ([]bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	res := make([]bool, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.di[req.Addr+i])
	}
	return res, nil
}

func (h *testHandler) HandleHoldingRegisters(req *modbus.HoldingRegistersRequest) ([]uint16, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.IsWrite {
		for i, v := range req.Args {
			h.hr[req.Addr+uint16(i)] = v
		}
		return nil, nil
	}
	res := make([]uint16, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.hr[req.Addr+i])
	}
	return res, nil
}

func (h *testHandler) HandleInputRegisters(req *modbus.InputRegistersRequest) ([]uint16, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	res := make([]uint16, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.ir[req.Addr+i])
	}
	return res, nil
}

// newTestDriver starts an in-memory server and returns a driver connected to it (auto-cleanup on test end).
func newTestDriver(t *testing.T, handler *testHandler, port string) *driver {
	t.Helper()
	server, err := modbus.NewServer(&modbus.ServerConfiguration{URL: "tcp://127.0.0.1:" + port}, handler)
	assert.Nil(t, err)
	assert.Nil(t, server.Start())
	t.Cleanup(func() { _ = server.Stop() })

	client, err := modbus.NewClient(&modbus.ClientConfiguration{URL: "tcp://127.0.0.1:" + port})
	assert.Nil(t, err)
	assert.Nil(t, client.Open())
	t.Cleanup(func() { _ = client.Close() })

	retryable := NewRetryableModbusClient(client, 0, nil, nil, 1, modbus.BIG_ENDIAN, modbus.HIGH_WORD_FIRST, nil)
	return newDriver(retryable)
}

// TestDriver_WriteThenRead writes then reads HR, verifying Type mapping + multi-register codec + Modicon parsing.
func TestDriver_WriteThenRead(t *testing.T) {
	d := newTestDriver(t, newTestHandler(), "5502")

	// write: FLOAT32@40001, UINT16@40010
	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "temp", Addr: "40001", Type: iot_points.TypeFloat32, Value: "23.5"},
		{Name: "count", Addr: "40010", Type: iot_points.TypeUint16, Value: "1234"},
	}))

	// read back
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "temp", Addr: "40001", Type: iot_points.TypeFloat32},
		{Name: "count", Addr: "40010", Type: iot_points.TypeUint16},
	})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(data))
	assert.Equal(t, "temp", data[0].Name)
	assert.Equal(t, float32(23.5), data[0].Value)
	assert.Equal(t, uint16(1234), data[1].Value)
}

// TestDriver_SignedIntRoundTrip: signed integer negative value round-trip, guards C1 (INT16/32/64 must read back signed; before the fix -1 read as 65535).
func TestDriver_SignedIntRoundTrip(t *testing.T) {
	d := newTestDriver(t, newTestHandler(), "5503")

	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "i16", Addr: "40001", Type: iot_points.TypeInt16, Value: "-1"},
		{Name: "i32", Addr: "40010", Type: iot_points.TypeInt32, Value: "-100000"},
		{Name: "i64", Addr: "40020", Type: iot_points.TypeInt64, Value: "-12345678901"},
	}))

	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "i16", Addr: "40001", Type: iot_points.TypeInt16},
		{Name: "i32", Addr: "40010", Type: iot_points.TypeInt32},
		{Name: "i64", Addr: "40020", Type: iot_points.TypeInt64},
	})
	assert.Nil(t, err)
	assert.Equal(t, 3, len(data))
	assert.Equal(t, int16(-1), data[0].Value)
	assert.Equal(t, int32(-100000), data[1].Value)
	assert.Equal(t, int64(-12345678901), data[2].Value)
}

// TestDriver_CoilAndDiscreteInput: Coil write-read + DI prefilled read, verifying BOOL + 0xxxx/1xxxx.
func TestDriver_CoilAndDiscreteInput(t *testing.T) {
	handler := newTestHandler()
	handler.di[0] = true // DI 10001 prefilled
	d := newTestDriver(t, handler, "5503")

	// write coil 00001 = true
	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "motor", Addr: "00001", Type: iot_points.TypeBool, Value: "true"},
	}))
	// read coil 00001 + DI 10001
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "motor", Addr: "00001", Type: iot_points.TypeBool},
		{Name: "di0", Addr: "10001", Type: iot_points.TypeBool},
	})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(data))
	assert.Equal(t, true, data[0].Value) // coil
	assert.Equal(t, true, data[1].Value) // DI prefilled
}

// TestDriver_InputRegister: IR prefilled read, verifying 3xxxx + INPUT_REGISTER.
func TestDriver_InputRegister(t *testing.T) {
	handler := newTestHandler()
	handler.ir[0] = 5678 // IR 30001 prefilled
	d := newTestDriver(t, handler, "5504")

	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "in", Addr: "30001", Type: iot_points.TypeUint16},
	})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(data))
	assert.Equal(t, uint16(5678), data[0].Value)
}

// TestDriver_WriteReadOnlyReject: DI/IR read-only rejects write.
func TestDriver_WriteReadOnlyReject(t *testing.T) {
	d := newTestDriver(t, newTestHandler(), "5505")

	err := d.WritePoints([]iot_points.Point{{Name: "x", Addr: "10001", Type: iot_points.TypeBool, Value: "true"}})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "read-only")

	err = d.WritePoints([]iot_points.Point{{Name: "x", Addr: "30001", Type: iot_points.TypeUint16, Value: "1"}})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "read-only")
}

// TestDriver_Scale: engineering unit conversion.
func TestDriver_Scale(t *testing.T) {
	d := newTestDriver(t, newTestHandler(), "5506")

	// write raw value 100, scale=0.1 on read -> 10.0
	assert.Nil(t, d.WritePoints([]iot_points.Point{
		{Name: "raw", Addr: "40001", Type: iot_points.TypeUint16, Value: "100"},
	}))
	data, err := d.ReadPoints([]iot_points.Point{
		{Name: "raw", Addr: "40001", Type: iot_points.TypeUint16, Scale: 0.1},
	})
	assert.Nil(t, err)
	assert.Equal(t, 10.0, data[0].Value) // 100 * 0.1
}
