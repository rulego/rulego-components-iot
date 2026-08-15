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

package iec104

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	iec104client "github.com/rulego/rulego-components-iot/pkg/iec104_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
	"github.com/rulego/rulego-components-iot/third_party/go-iecp5/asdu"
	iec104server "github.com/rulego/rulego-components-iot/third_party/iec104/server"
)

const testCA = 1

// mockHandler simulates IEC 104 substation: on interrogation upload single point (IOA=100) and short float (IOA=700), then activation termination
type mockHandler struct{}

func (m *mockHandler) OnInterrogation(conn asdu.Connect, _ *asdu.ASDU, qoi asdu.QualifierOfInterrogation) error {
	coaData := asdu.CauseOfTransmission{Cause: asdu.InterrogatedByStation}
	_ = asdu.Single(conn, false, coaData, testCA, asdu.SinglePointInfo{Ioa: 100, Value: true, Qds: asdu.QDSGood})
	_ = asdu.MeasuredValueFloat(conn, false, coaData, testCA, asdu.MeasuredValueFloatInfo{Ioa: 700, Value: 123.5, Qds: asdu.QDSGood})

	// Activation termination (ActTerm): manually construct C_IC_NA_1 to end current general interrogation per protocol
	u := asdu.NewASDU(conn.Params(), asdu.Identifier{
		Type:       asdu.C_IC_NA_1,
		Variable:   asdu.VariableStruct{IsSequence: false, Number: 1},
		Coa:        asdu.CauseOfTransmission{Cause: asdu.ActivationTerm},
		CommonAddr: testCA,
	})
	_ = u.AppendInfoObjAddr(asdu.InfoObjAddrIrrelevant)
	u.AppendBytes(byte(qoi))
	_ = conn.Send(u)
	return nil
}

func (m *mockHandler) OnCounterInterrogation(asdu.Connect, *asdu.ASDU, asdu.QualifierCountCall) error {
	return nil
}
func (m *mockHandler) OnRead(asdu.Connect, *asdu.ASDU, asdu.InfoObjAddr) error { return nil }
func (m *mockHandler) OnClockSync(asdu.Connect, *asdu.ASDU, time.Time) error   { return nil }
func (m *mockHandler) OnResetProcess(asdu.Connect, *asdu.ASDU, asdu.QualifierOfResetProcessCmd) error {
	return nil
}
func (m *mockHandler) OnDelayAcquisition(asdu.Connect, *asdu.ASDU, uint16) error { return nil }
func (m *mockHandler) OnTestCommand(asdu.Connect, *asdu.ASDU) error              { return nil }
func (m *mockHandler) OnASDU(asdu.Connect, *asdu.ASDU) error                     { return nil }

// startMockServer starts in-process IEC 104 substation, returns port and cleanup function
func startMockServer(t *testing.T) (int, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free port (skip iec104 mock test): %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	settings := iec104server.NewSettings()
	settings.Host = "127.0.0.1"
	settings.Port = port
	settings.LogCfg = &iec104server.LogCfg{Enable: false}
	srv := iec104server.New(settings, &mockHandler{})
	srv.Start()
	time.Sleep(200 * time.Millisecond) // Wait for listener ready
	return port, func() { srv.Stop() }
}

// newTestClient connects to mock substation
func newTestClient(t *testing.T, port int) *iec104client.Client {
	client, err := iec104client.DefaultHolder(Configuration{
		Server:     fmt.Sprintf("127.0.0.1:%d", port),
		CommonAddr: testCA,
		Timeout:    5,
	}).NewClient()
	if err != nil {
		t.Fatalf("connect mock server: %v", err)
	}
	return client
}

// TestReadNodeType node types and default configurations
func TestReadNodeType(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/iec104Read", r.Type())
	assert.NotNil(t, r.New())
	assert.True(t, strings.Contains(r.Desc(), "IEC"))

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:2404", rn.Config.Server)
	assert.Equal(t, 1, rn.Config.CommonAddr)
}

// TestToIec104Point unified Point (Addr=IOA string) mapping to iec104client.Point
func TestToIec104Point(t *testing.T) {
	p, err := toIec104Point(iot_points.Point{Name: "switch", Addr: "100"})
	assert.Nil(t, err)
	assert.Equal(t, "switch", p.Name)
	assert.Equal(t, uint(100), p.Ioa)

	// Allow leading/trailing whitespace
	p, err = toIec104Point(iot_points.Point{Name: "switch", Addr: " 200 "})
	assert.Nil(t, err)
	assert.Equal(t, uint(200), p.Ioa)

	// Invalid IOA
	_, err = toIec104Point(iot_points.Point{Name: "bad_point", Addr: "abc"})
	assert.NotNil(t, err)
}

// TestParseControlCmd command type parsing
func TestParseControlCmd(t *testing.T) {
	// Single command
	typeId, val, err := parseControlCmd(iot_points.Point{Type: "C_SC_NA_1", Value: "true"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SC_NA_1, typeId)
	assert.Equal(t, true, val)

	typeId, val, err = parseControlCmd(iot_points.Point{Type: "SINGLE", Value: "0"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SC_NA_1, typeId)
	assert.Equal(t, false, val)

	// Double command
	typeId, val, err = parseControlCmd(iot_points.Point{Type: "C_DC_NA_1", Value: "2"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_DC_NA_1, typeId)
	assert.Equal(t, uint8(2), val)

	// Scaled setpoint
	typeId, val, err = parseControlCmd(iot_points.Point{Type: "C_SE_NB_1", Value: "-100"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SE_NB_1, typeId)
	assert.Equal(t, int16(-100), val)

	// Short floating point setpoint
	typeId, val, err = parseControlCmd(iot_points.Point{Type: "C_SE_NC_1", Value: "3.14"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SE_NC_1, typeId)

	// Unknown type
	_, _, err = parseControlCmd(iot_points.Point{Type: "UNKNOWN", Value: "1"})
	assert.NotNil(t, err)
}

// TestWriteNodeEndToEnd x/iec104Write node end-to-end: send single command + setpoint
func TestWriteNodeEndToEnd(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/iec104Write", types.Configuration{
		"server":     fmt.Sprintf("127.0.0.1:%d", port),
		"commonAddr": testCA,
		"timeout":    5,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `[{"name":"switch","addr":"100","type":"C_SC_NA_1","value":"true"},{"name":"setpoint","addr":"700","type":"C_SE_NC_1","value":"50.5"}]`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for iec104 write callback")
	}
}

// TestWriteNodeBadType unsupported command type -> Failure
func TestWriteNodeBadType(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/iec104Write", types.Configuration{
		"server":     fmt.Sprintf("127.0.0.1:%d", port),
		"commonAddr": testCA,
		"timeout":    5,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `[{"name":"bad_command","addr":"100","type":"INVALID","value":"1"}]`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		assert.NotNil(t, err)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for iec104 bad-type callback")
	}
}

// TestDriverReadPoints driver end-to-end: general interrogation collection -> unified Data output
func TestDriverReadPoints(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()
	client := newTestClient(t, port)
	defer client.Close()

	data, err := newDriver(client).ReadPoints([]iot_points.Point{
		{Name: "single_point", Addr: "100"},
		{Name: "short_float", Addr: "700"},
	})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(data))

	byName := make(map[string]iot_points.Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, true, byName["single_point"].Value)
	assert.Equal(t, 123.5, byName["short_float"].Value)
	assert.True(t, byName["single_point"].Timestamp > 0, "timestamp should be unix nano")
}

// TestDriverReadPointsBadAddr ReadPoints returns error when point IOA is invalid
func TestDriverReadPointsBadAddr(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()
	client := newTestClient(t, port)
	defer client.Close()

	_, err := newDriver(client).ReadPoints([]iot_points.Point{{Name: "bad_point", Addr: "not-a-ioa"}})
	assert.NotNil(t, err)
}

// TestReadNodeEndToEnd x/iec104Read node end-to-end: mock substation -> general interrogation -> output unified Data list
func TestReadNodeEndToEnd(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/iec104Read", types.Configuration{
		"server":     fmt.Sprintf("127.0.0.1:%d", port),
		"commonAddr": testCA,
		"timeout":    5,
		"points": []map[string]interface{}{
			{"name": "single_point", "addr": "100"},
			{"name": "short_float", "addr": "700"},
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
		assert.True(t, strings.Contains(msg.GetData(), "single_point"), "msg.Data should contain single_point")
		assert.True(t, strings.Contains(msg.GetData(), "short_float"), "msg.Data should contain short_float")
		assert.True(t, strings.Contains(msg.GetData(), "123.5"), "msg.Data should contain 123.5")
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for iec104 read callback")
	}
}

// TestReadNodeMsgPoints msg.Data points take precedence over configured points (dynamic collection scenario)
func TestReadNodeMsgPoints(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/iec104Read", types.Configuration{
		"server":     fmt.Sprintf("127.0.0.1:%d", port),
		"commonAddr": testCA,
		"timeout":    5,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `[{"name":"dynamic_point","addr":"700"}]`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		assert.True(t, strings.Contains(msg.GetData(), "dynamic_point"), "msg.Data should contain dynamic_point")
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for iec104 dynamic points callback")
	}
}

// TestReadNodeNoPoints no configured points and no msg.Data points -> Failure
func TestReadNodeNoPoints(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/iec104Read", types.Configuration{
		"server":     fmt.Sprintf("127.0.0.1:%d", port),
		"commonAddr": testCA,
		"timeout":    5,
		"points":     []map[string]interface{}{}, // Explicit empty points, override New() default points
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		assert.NotNil(t, err)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for iec104 no-points callback")
	}
}
