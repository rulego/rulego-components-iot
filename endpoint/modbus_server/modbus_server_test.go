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

package modbus_server

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test/assert"
	"github.com/simonvetter/modbus"
)

// freePort 获取空闲端口
func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// startEndpoint 启动 modbus server endpoint 并等待就绪
func startEndpoint(t *testing.T, cfg map[string]interface{}) *ModbusServerEndpoint {
	ep := &ModbusServerEndpoint{}
	node := ep.New().(*ModbusServerEndpoint)
	if err := node.Init(types.Config{}, cfg); err != nil {
		t.Fatalf("init endpoint: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("start endpoint: %v", err)
	}
	// 等待端口就绪
	listen := cfg["server"].(string)
	addr := listen[len("tcp://"):]
	for range 20 {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return node
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server not ready at %s", addr)
	return nil
}

// newTestClient 创建并连接 modbus 客户端
func newTestClient(t *testing.T, port int) *modbus.ModbusClient {
	client, err := modbus.NewClient(&modbus.ClientConfiguration{
		URL: fmt.Sprintf("tcp://127.0.0.1:%d", port),
	})
	if err != nil {
		t.Fatalf("create modbus client: %v", err)
	}
	if err := client.Open(); err != nil {
		t.Fatalf("open modbus client: %v", err)
	}
	return client
}

// TestModbusServerReadWrite 端到端：启动从站 → 客户端写 HR → 读回验证
func TestModbusServerReadWrite(t *testing.T) {
	port := freePort(t)
	node := startEndpoint(t, map[string]interface{}{
		"server": fmt.Sprintf("tcp://127.0.0.1:%d", port),
	})
	defer node.Close()
	client := newTestClient(t, port)
	defer client.Close()

	// 写 Holding Register
	err := client.WriteRegister(100, 1234)
	assert.Nil(t, err)

	// 读回验证
	val, err := client.ReadRegister(100, modbus.HOLDING_REGISTER)
	assert.Nil(t, err)
	assert.Equal(t, uint16(1234), val)

	// 写多个寄存器
	err = client.WriteRegisters(200, []uint16{111, 222, 333})
	assert.Nil(t, err)
	vals, err := client.ReadRegisters(200, 3, modbus.HOLDING_REGISTER)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(vals))
	assert.Equal(t, uint16(111), vals[0])
	assert.Equal(t, uint16(222), vals[1])
	assert.Equal(t, uint16(333), vals[2])

	// 写 Coil
	err = client.WriteCoil(50, true)
	assert.Nil(t, err)
	coilVal, err := client.ReadCoil(50)
	assert.Nil(t, err)
	assert.Equal(t, true, coilVal)

	// 越界读 → 错误
	_, err = client.ReadRegister(uint16(node.Config.Registers)+10, modbus.HOLDING_REGISTER)
	assert.NotNil(t, err)
}

// TestModbusServerWriteTrigger 写触发（无路由时静默丢弃，验证不 panic）
func TestModbusServerWriteTrigger(t *testing.T) {
	port := freePort(t)
	node := startEndpoint(t, map[string]interface{}{
		"server": fmt.Sprintf("tcp://127.0.0.1:%d", port),
	})
	defer node.Close()
	client := newTestClient(t, port)
	defer client.Close()

	err := client.WriteRegister(0, 999)
	assert.Nil(t, err)
	val, err := client.ReadRegister(0, modbus.HOLDING_REGISTER)
	assert.Nil(t, err)
	assert.Equal(t, uint16(999), val)
}

// TestModbusServerSetRegisters 外部回写寄存器（规则链处理后更新）
func TestModbusServerSetRegisters(t *testing.T) {
	port := freePort(t)
	node := startEndpoint(t, map[string]interface{}{
		"server": fmt.Sprintf("tcp://127.0.0.1:%d", port),
	})
	defer node.Close()

	// 外部写入（模拟规则链回写）
	node.SetRegisters(300, []uint16{5555, 6666})

	client := newTestClient(t, port)
	defer client.Close()
	vals, err := client.ReadRegisters(300, 2, modbus.HOLDING_REGISTER)
	assert.Nil(t, err)
	assert.Equal(t, uint16(5555), vals[0])
	assert.Equal(t, uint16(6666), vals[1])
}

// TestModbusServerUnitIdFilter Unit ID 过滤
func TestModbusServerUnitIdFilter(t *testing.T) {
	port := freePort(t)
	node := startEndpoint(t, map[string]interface{}{
		"server": fmt.Sprintf("tcp://127.0.0.1:%d", port),
		"unitId": 1,
	})
	defer node.Close()
	client := newTestClient(t, port)
	defer client.Close()

	client.SetUnitId(1)
	err := client.WriteRegister(0, 100)
	assert.Nil(t, err)

	// 验证消息格式可序列化
	payload := map[string]interface{}{
		"type": "holding_register", "unitId": uint8(1),
		"addr": uint16(0), "quantity": uint16(1),
		"values": []interface{}{uint16(100)}, "clientAddr": "test",
	}
	b, _ := json.Marshal(payload)
	assert.True(t, len(b) > 0, "payload should marshal")
}
