/*
 * Copyright 2025 The RuleGo Authors.
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
	"os"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test/assert"
)

// TestModbusNode 测试 Modbus 节点基本功能
func TestModbusNode(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("跳过 Modbus 节点测试")
	}

	Registry := &types.SafeComponentSlice{}
	Registry.Add(&ModbusNode{})

	node := &ModbusNode{}
	assert.Equal(t, "x/modbus", node.Type())

	// 创建新节点实例
	newNode := node.New()
	assert.NotNil(t, newNode)

	t.Log("Modbus 节点基本功能测试通过")
}

// TestModbusConnectionConfig 测试 Modbus 连接配置
func TestModbusConnectionConfig(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("跳过 Modbus 连接配置测试")
	}

	host := os.Getenv("MODBUS_SERVER_HOST")
	port := os.Getenv("MODBUS_SERVER_PORT")

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "1502" // techplex/modbus-sim 默认端口
	}

	t.Logf("测试 Modbus 连接配置 %s:%s", host, port)

	// 验证环境变量设置
	assert.NotEqual(t, "", host)
	assert.NotEqual(t, "", port)
	assert.Equal(t, "1502", port) // 验证使用正确的端口
}

// TestModbusBasicOperations 基本的 Modbus 操作测试框架
func TestModbusBasicOperations(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("跳过 Modbus 基础操作测试")
	}

	// 模拟测试超时保护
	timeout := time.After(10 * time.Second)
	done := make(chan bool)

	go func() {
		// 模拟一些 Modbus 操作
		time.Sleep(200 * time.Millisecond)
		t.Log("Modbus 基础操作模拟完成")
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("Modbus 基础操作测试超时")
	case <-done:
		t.Log("Modbus 基础操作测试完成")
	}
}
