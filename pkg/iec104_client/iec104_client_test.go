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

package iec104client

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rulego/rulego/test/assert"
	"github.com/rulego/rulego-components-iot/third_party/go-iecp5/asdu"
	iec104server "github.com/rulego/rulego-components-iot/third_party/iec104/server"
)

const testCA = 1

// mockHandler simulates IEC 104 slave. Sends various type data after receiving general interrogation and responds with activation termination.
type mockHandler struct{}

func (m *mockHandler) OnInterrogation(conn asdu.Connect, _ *asdu.ASDU, qoi asdu.QualifierOfInterrogation) error {
	coaData := asdu.CauseOfTransmission{Cause: asdu.InterrogatedByStation}
	// Single point signal IOA=100
	_ = asdu.Single(conn, false, coaData, testCA, asdu.SinglePointInfo{Ioa: 100, Value: true, Qds: asdu.QDSGood})
	// Double point signal IOA=200
	_ = asdu.Double(conn, false, coaData, testCA, asdu.DoublePointInfo{Ioa: 200, Value: asdu.DPIDeterminedOn, Qds: asdu.QDSGood})
	// Step position IOA=300
	_ = asdu.Step(conn, false, coaData, testCA, asdu.StepPositionInfo{Ioa: 300, Value: asdu.StepPosition{Val: 10}, Qds: asdu.QDSGood})
	// Bit string IOA=400
	_ = asdu.BitString32(conn, false, coaData, testCA, asdu.BitString32Info{Ioa: 400, Value: 0x12345678, Qds: asdu.QDSGood})
	// Normalized measured value IOA=500 -> 0.5
	_ = asdu.MeasuredValueNormal(conn, false, coaData, testCA, asdu.MeasuredValueNormalInfo{Ioa: 500, Value: asdu.Normalize(16384), Qds: asdu.QDSGood})
	// Scaled measured value IOA=600 -> 100
	_ = asdu.MeasuredValueScaled(conn, false, coaData, testCA, asdu.MeasuredValueScaledInfo{Ioa: 600, Value: 100, Qds: asdu.QDSGood})
	// Short floating point measured value IOA=700 -> 123.5 (float32 precision)
	_ = asdu.MeasuredValueFloat(conn, false, coaData, testCA, asdu.MeasuredValueFloatInfo{Ioa: 700, Value: 123.5, Qds: asdu.QDSGood})
	// Integrated total IOA=800 -> 999 (integrated total transmission cause must be counter interrogation)
	coaCount := asdu.CauseOfTransmission{Cause: asdu.RequestByGeneralCounter}
	_ = asdu.IntegratedTotals(conn, false, coaCount, testCA, asdu.BinaryCounterReadingInfo{Ioa: 800, Value: asdu.BinaryCounterReading{CounterReading: 999, SeqNumber: 1}})

	// Activation termination (ActTerm): high-level InterrogationCmd only allows Activation/Deactivation causes,
	// here manually construct C_IC_NA_1 ActTerm per protocol to simulate real slave GI completion.
	sendInterrogationTerm(conn, qoi)
	return nil
}

// sendInterrogationTerm manually constructs and sends general interrogation activation termination ASDU
func sendInterrogationTerm(conn asdu.Connect, qoi asdu.QualifierOfInterrogation) {
	u := asdu.NewASDU(conn.Params(), asdu.Identifier{
		Type:       asdu.C_IC_NA_1,
		Variable:   asdu.VariableStruct{IsSequence: false, Number: 1},
		Coa:        asdu.CauseOfTransmission{Cause: asdu.ActivationTerm},
		CommonAddr: testCA,
	})
	_ = u.AppendInfoObjAddr(asdu.InfoObjAddrIrrelevant)
	u.AppendBytes(byte(qoi))
	_ = conn.Send(u)
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

// startMockServer starts in-process IEC 104 slave, returns port and cleanup function
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

// testConfig test connection configuration
type testConfig struct {
	server  string
	timeout int
}

func (c testConfig) GetServer() string  { return c.server }
func (c testConfig) GetCommonAddr() int { return testCA }
func (c testConfig) GetTimeout() int    { return c.timeout }

// TestReadPointsEndToEnd end-to-end: master connects to slave -> general interrogation -> various type point acquisition verification
func TestReadPointsEndToEnd(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	client, err := DefaultHolder(testConfig{server: fmt.Sprintf("127.0.0.1:%d", port), timeout: 5}).NewClient()
	if err != nil {
		t.Fatalf("connect mock server: %v", err)
	}
	defer client.Close()

	points := []Point{
		{Name: "SinglePoint", Ioa: 100},
		{Name: "DoublePoint", Ioa: 200},
		{Name: "StepPosition", Ioa: 300},
		{Name: "BitString", Ioa: 400},
		{Name: "Normalized", Ioa: 500},
		{Name: "Scaled", Ioa: 600},
		{Name: "ShortFloat", Ioa: 700},
		{Name: "Accumulated", Ioa: 800},
	}
	data, err := client.ReadPoints(points)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(data))

	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, "good", byName["SinglePoint"].Quality)
	assert.Equal(t, true, byName["SinglePoint"].Value)
	assert.Equal(t, int(asdu.DPIDeterminedOn), byName["DoublePoint"].Value)
	assert.Equal(t, 10, byName["StepPosition"].Value)
	assert.Equal(t, uint32(0x12345678), byName["BitString"].Value)
	assert.Equal(t, 0.5, byName["Normalized"].Value)
	assert.Equal(t, 100, byName["Scaled"].Value)
	assert.Equal(t, 123.5, byName["ShortFloat"].Value)
	assert.Equal(t, int64(999), byName["Accumulated"].Value)
}

// TestReadPointsMissingIOA partial IOAs not uploaded by slave: good/bad mixed, no error returned
func TestReadPointsMissingIOA(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	client, err := DefaultHolder(testConfig{server: fmt.Sprintf("127.0.0.1:%d", port), timeout: 3}).NewClient()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	points := []Point{
		{Name: "GoodPoint", Ioa: 700},
		{Name: "BadPoint", Ioa: 9999}, // Slave does not upload
	}
	data, err := client.ReadPoints(points)
	assert.Nil(t, err) // Single point missing does not return error (ends early after GI completes)
	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, "good", byName["GoodPoint"].Quality)
	assert.Equal(t, "bad", byName["BadPoint"].Quality)
}

// TestNewClientConnectFail NewClient returns error when connection fails
func TestNewClientConnectFail(t *testing.T) {
	_, err := DefaultHolder(testConfig{server: "127.0.0.1:19999", timeout: 2}).NewClient()
	assert.NotNil(t, err)
}

// invalidQdsHandler sends a single point with QDSInvalid to verify the quality->bad mapping.
type invalidQdsHandler struct{}

func (m *invalidQdsHandler) OnInterrogation(conn asdu.Connect, _ *asdu.ASDU, qoi asdu.QualifierOfInterrogation) error {
	coaData := asdu.CauseOfTransmission{Cause: asdu.InterrogatedByStation}
	// Valid point IOA=100
	_ = asdu.Single(conn, false, coaData, testCA, asdu.SinglePointInfo{Ioa: 100, Value: true, Qds: asdu.QDSGood})
	// Invalid-quality point IOA=101 (slave flags value as incorrectly acquired)
	_ = asdu.Single(conn, false, coaData, testCA, asdu.SinglePointInfo{Ioa: 101, Value: true, Qds: asdu.QDSInvalid})
	sendInterrogationTerm(conn, qoi)
	return nil
}

func (m *invalidQdsHandler) OnCounterInterrogation(asdu.Connect, *asdu.ASDU, asdu.QualifierCountCall) error {
	return nil
}
func (m *invalidQdsHandler) OnRead(asdu.Connect, *asdu.ASDU, asdu.InfoObjAddr) error { return nil }
func (m *invalidQdsHandler) OnClockSync(asdu.Connect, *asdu.ASDU, time.Time) error   { return nil }
func (m *invalidQdsHandler) OnResetProcess(asdu.Connect, *asdu.ASDU, asdu.QualifierOfResetProcessCmd) error {
	return nil
}
func (m *invalidQdsHandler) OnDelayAcquisition(asdu.Connect, *asdu.ASDU, uint16) error { return nil }
func (m *invalidQdsHandler) OnTestCommand(asdu.Connect, *asdu.ASDU) error              { return nil }
func (m *invalidQdsHandler) OnASDU(asdu.Connect, *asdu.ASDU) error                     { return nil }

// TestReadPointsQDSInvalid: a value flagged QDSInvalid by the slave must be reported as
// quality=bad (not good), so downstream can drop or alert on it.
func TestReadPointsQDSInvalid(t *testing.T) {
	port := freePort(t)
	settings := iec104server.NewSettings()
	settings.Host = "127.0.0.1"
	settings.Port = port
	settings.LogCfg = &iec104server.LogCfg{Enable: false}
	srv := iec104server.New(settings, &invalidQdsHandler{})
	srv.Start()
	defer srv.Stop()
	time.Sleep(200 * time.Millisecond)

	client, err := DefaultHolder(testConfig{server: fmt.Sprintf("127.0.0.1:%d", port), timeout: 5}).NewClient()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	points := []Point{
		{Name: "Good", Ioa: 100},
		{Name: "Invalid", Ioa: 101},
	}
	data, err := client.ReadPoints(points)
	assert.Nil(t, err)
	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, "good", byName["Good"].Quality)
	assert.Equal(t, "bad", byName["Invalid"].Quality, "QDSInvalid point should be quality=bad")
}

// freePort reserves and releases a TCP port for the mock server.
func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
