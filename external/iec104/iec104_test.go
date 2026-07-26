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
	"github.com/wendy512/go-iecp5/asdu"
	iec104server "github.com/wendy512/iec104/server"
)

const testCA = 1

// mockHandler 模拟 IEC 104 子站：总召唤时上送单点(IOA=100)与短浮点(IOA=700)，回激活停止
type mockHandler struct{}

func (m *mockHandler) OnInterrogation(conn asdu.Connect, _ *asdu.ASDU, qoi asdu.QualifierOfInterrogation) error {
	coaData := asdu.CauseOfTransmission{Cause: asdu.InterrogatedByStation}
	_ = asdu.Single(conn, false, coaData, testCA, asdu.SinglePointInfo{Ioa: 100, Value: true, Qds: asdu.QDSGood})
	_ = asdu.MeasuredValueFloat(conn, false, coaData, testCA, asdu.MeasuredValueFloatInfo{Ioa: 700, Value: 123.5, Qds: asdu.QDSGood})

	// 激活停止(ActTerm)：按协议手工构造 C_IC_NA_1 结束本轮总召唤
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

// startMockServer 启动进程内 IEC 104 子站，返回端口与清理函数
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

// newTestClient 连接 mock 子站
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

// TestReadNodeType 节点类型与默认配置
func TestReadNodeType(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/iec104Read", r.Type())
	assert.NotNil(t, r.New())
	assert.True(t, strings.Contains(r.Desc(), "IEC"))

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:2404", rn.Config.Server)
	assert.Equal(t, 1, rn.Config.CommonAddr)
}

// TestToIec104Point 统一 Point(Addr=IOA 字符串) 映射为 iec104client.Point
func TestToIec104Point(t *testing.T) {
	p, err := toIec104Point(iot_points.Point{Name: "开关", Addr: "100"})
	assert.Nil(t, err)
	assert.Equal(t, "开关", p.Name)
	assert.Equal(t, uint(100), p.Ioa)

	// 允许首尾空白
	p, err = toIec104Point(iot_points.Point{Name: "开关", Addr: " 200 "})
	assert.Nil(t, err)
	assert.Equal(t, uint(200), p.Ioa)

	// 非法 IOA
	_, err = toIec104Point(iot_points.Point{Name: "坏点", Addr: "abc"})
	assert.NotNil(t, err)
}

// TestParseControlCmd 命令类型解析
func TestParseControlCmd(t *testing.T) {
	// 单命令
	typeId, val, err := parseControlCmd(iot_points.Point{Type: "C_SC_NA_1", Value: "true"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SC_NA_1, typeId)
	assert.Equal(t, true, val)

	typeId, val, err = parseControlCmd(iot_points.Point{Type: "SINGLE", Value: "0"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SC_NA_1, typeId)
	assert.Equal(t, false, val)

	// 双命令
	typeId, val, err = parseControlCmd(iot_points.Point{Type: "C_DC_NA_1", Value: "2"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_DC_NA_1, typeId)
	assert.Equal(t, uint8(2), val)

	// 标度化设点
	typeId, val, err = parseControlCmd(iot_points.Point{Type: "C_SE_NB_1", Value: "-100"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SE_NB_1, typeId)
	assert.Equal(t, int16(-100), val)

	// 短浮点设点
	typeId, val, err = parseControlCmd(iot_points.Point{Type: "C_SE_NC_1", Value: "3.14"})
	assert.Nil(t, err)
	assert.Equal(t, asdu.C_SE_NC_1, typeId)

	// 未知类型
	_, _, err = parseControlCmd(iot_points.Point{Type: "UNKNOWN", Value: "1"})
	assert.NotNil(t, err)
}

// TestWriteNodeEndToEnd x/iec104Write 节点端到端：下发单命令+设点
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
		Data:     `[{"name":"开关","addr":"100","type":"C_SC_NA_1","value":"true"},{"name":"设定值","addr":"700","type":"C_SE_NC_1","value":"50.5"}]`,
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

// TestWriteNodeBadType 不支持的命令类型 -> Failure
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
		Data:     `[{"name":"坏命令","addr":"100","type":"INVALID","value":"1"}]`,
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

// TestDriverReadPoints driver 端到端：总召唤采集 -> 统一 Data 输出
func TestDriverReadPoints(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()
	client := newTestClient(t, port)
	defer client.Close()

	data, err := newDriver(client).ReadPoints([]iot_points.Point{
		{Name: "单点", Addr: "100"},
		{Name: "短浮点", Addr: "700"},
	})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(data))

	byName := make(map[string]iot_points.Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, true, byName["单点"].Value)
	assert.Equal(t, 123.5, byName["短浮点"].Value)
	assert.True(t, byName["单点"].Timestamp > 0, "timestamp should be unix nano")
}

// TestDriverReadPointsBadAddr 点位 IOA 非法时 ReadPoints 返回错误
func TestDriverReadPointsBadAddr(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()
	client := newTestClient(t, port)
	defer client.Close()

	_, err := newDriver(client).ReadPoints([]iot_points.Point{{Name: "坏点", Addr: "not-a-ioa"}})
	assert.NotNil(t, err)
}

// TestReadNodeEndToEnd x/iec104Read 节点端到端：mock 子站 -> 总召唤 -> 输出统一 Data 列表
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
			{"name": "单点", "addr": "100"},
			{"name": "短浮点", "addr": "700"},
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
		assert.True(t, strings.Contains(msg.GetData(), "单点"), "msg.Data should contain 单点")
		assert.True(t, strings.Contains(msg.GetData(), "短浮点"), "msg.Data should contain 短浮点")
		assert.True(t, strings.Contains(msg.GetData(), "123.5"), "msg.Data should contain 123.5")
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for iec104 read callback")
	}
}

// TestReadNodeMsgPoints msg.Data 带点位优先于配置点位（动态采集场景）
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
		Data:     `[{"name":"动态点","addr":"700"}]`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		assert.True(t, strings.Contains(msg.GetData(), "动态点"), "msg.Data should contain 动态点")
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for iec104 dynamic points callback")
	}
}

// TestReadNodeNoPoints 未配置点位且 msg.Data 无点位 -> Failure
func TestReadNodeNoPoints(t *testing.T) {
	port, cleanup := startMockServer(t)
	defer cleanup()

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/iec104Read", types.Configuration{
		"server":     fmt.Sprintf("127.0.0.1:%d", port),
		"commonAddr": testCA,
		"timeout":    5,
		"points":     []map[string]interface{}{}, // 显式空点位，覆盖 New() 默认点位
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
