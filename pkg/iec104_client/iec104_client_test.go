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
	"github.com/wendy512/go-iecp5/asdu"
	iec104server "github.com/wendy512/iec104/server"
)

const testCA = 1

// mockHandler 模拟 IEC 104 子站。收到总召唤后上送各类型数据并回激活停止。
type mockHandler struct{}

func (m *mockHandler) OnInterrogation(conn asdu.Connect, _ *asdu.ASDU, qoi asdu.QualifierOfInterrogation) error {
	coaData := asdu.CauseOfTransmission{Cause: asdu.InterrogatedByStation}
	// 单点遥信 IOA=100
	_ = asdu.Single(conn, false, coaData, testCA, asdu.SinglePointInfo{Ioa: 100, Value: true, Qds: asdu.QDSGood})
	// 双点遥信 IOA=200
	_ = asdu.Double(conn, false, coaData, testCA, asdu.DoublePointInfo{Ioa: 200, Value: asdu.DPIDeterminedOn, Qds: asdu.QDSGood})
	// 步位置 IOA=300
	_ = asdu.Step(conn, false, coaData, testCA, asdu.StepPositionInfo{Ioa: 300, Value: asdu.StepPosition{Val: 10}, Qds: asdu.QDSGood})
	// 比特位串 IOA=400
	_ = asdu.BitString32(conn, false, coaData, testCA, asdu.BitString32Info{Ioa: 400, Value: 0x12345678, Qds: asdu.QDSGood})
	// 归一化遥测 IOA=500 -> 0.5
	_ = asdu.MeasuredValueNormal(conn, false, coaData, testCA, asdu.MeasuredValueNormalInfo{Ioa: 500, Value: asdu.Normalize(16384), Qds: asdu.QDSGood})
	// 标度化遥测 IOA=600 -> 100
	_ = asdu.MeasuredValueScaled(conn, false, coaData, testCA, asdu.MeasuredValueScaledInfo{Ioa: 600, Value: 100, Qds: asdu.QDSGood})
	// 短浮点遥测 IOA=700 -> 123.5(float32 精确)
	_ = asdu.MeasuredValueFloat(conn, false, coaData, testCA, asdu.MeasuredValueFloatInfo{Ioa: 700, Value: 123.5, Qds: asdu.QDSGood})
	// 累计量 IOA=800 -> 999(累计量传送原因须为计数量召唤)
	coaCount := asdu.CauseOfTransmission{Cause: asdu.RequestByGeneralCounter}
	_ = asdu.IntegratedTotals(conn, false, coaCount, testCA, asdu.BinaryCounterReadingInfo{Ioa: 800, Value: asdu.BinaryCounterReading{CounterReading: 999, SeqNumber: 1}})

	// 激活停止(ActTerm)：高层 InterrogationCmd 仅允许 Activation/Deactivation 原因,
	// 这里按协议手工构造 C_IC_NA_1 ActTerm,模拟真实子站总召唤结束。
	sendInterrogationTerm(conn, qoi)
	return nil
}

// sendInterrogationTerm 手工构造并发送总召唤激活停止 ASDU
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

// startMockServer 启动进程内 IEC 104 子站,返回端口与清理函数。
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
	time.Sleep(200 * time.Millisecond) // 等待监听就绪
	return port, func() { srv.Stop() }
}

// testConfig 测试用连接配置
type testConfig struct {
	server  string
	timeout int
}

func (c testConfig) GetServer() string  { return c.server }
func (c testConfig) GetCommonAddr() int { return testCA }
func (c testConfig) GetTimeout() int    { return c.timeout }

// TestReadPointsEndToEnd 端到端：主站连子站 -> 总召唤 -> 各类型点位采集验证
func TestReadPointsEndToEnd(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	client, err := DefaultHolder(testConfig{server: fmt.Sprintf("127.0.0.1:%d", port), timeout: 5}).NewClient()
	if err != nil {
		t.Fatalf("connect mock server: %v", err)
	}
	defer client.Close()

	points := []Point{
		{Name: "单点", Ioa: 100},
		{Name: "双点", Ioa: 200},
		{Name: "步位置", Ioa: 300},
		{Name: "位串", Ioa: 400},
		{Name: "归一化", Ioa: 500},
		{Name: "标度化", Ioa: 600},
		{Name: "短浮点", Ioa: 700},
		{Name: "累计量", Ioa: 800},
	}
	data, err := client.ReadPoints(points)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(data))

	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, "good", byName["单点"].Quality)
	assert.Equal(t, true, byName["单点"].Value)
	assert.Equal(t, int(asdu.DPIDeterminedOn), byName["双点"].Value)
	assert.Equal(t, 10, byName["步位置"].Value)
	assert.Equal(t, uint32(0x12345678), byName["位串"].Value)
	assert.Equal(t, 0.5, byName["归一化"].Value)
	assert.Equal(t, 100, byName["标度化"].Value)
	assert.Equal(t, 123.5, byName["短浮点"].Value)
	assert.Equal(t, int64(999), byName["累计量"].Value)
}

// TestReadPointsMissingIOA 部分 IOA 子站未上送：good/bad 混合,不返回错误
func TestReadPointsMissingIOA(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	client, err := DefaultHolder(testConfig{server: fmt.Sprintf("127.0.0.1:%d", port), timeout: 3}).NewClient()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	points := []Point{
		{Name: "好点", Ioa: 700},
		{Name: "缺点", Ioa: 9999}, // 子站不上送
	}
	data, err := client.ReadPoints(points)
	assert.Nil(t, err) // 单点缺失不返回错误(GI 完成后提前结束)
	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, "good", byName["好点"].Quality)
	assert.Equal(t, "bad", byName["缺点"].Quality)
}

// TestReadPointsNotConnected 连接失败时 NewClient 返回错误
func TestNewClientConnectFail(t *testing.T) {
	_, err := DefaultHolder(testConfig{server: "127.0.0.1:19999", timeout: 2}).NewClient()
	assert.NotNil(t, err)
}
