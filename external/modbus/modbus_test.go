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
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
	"github.com/rulego/rulego/utils/str"
	"github.com/simonvetter/modbus"
)

// TestModbusNode tests Modbus node basic functionality
func TestModbusNode(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("Skipping Modbus node test")
	}

	Registry := &types.SafeComponentSlice{}
	Registry.Add(&ModbusNode{})

	node := &ModbusNode{}
	assert.Equal(t, "x/modbus", node.Type())

	// Create new node instance
	newNode := node.New()
	assert.NotNil(t, newNode)

	t.Log("Modbus node basic functionality test passed")
}

// TestModbusConnectionConfig tests Modbus connection configuration
func TestModbusConnectionConfig(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("skip Modbus connection config test")
	}

	host := os.Getenv("MODBUS_SERVER_HOST")
	port := os.Getenv("MODBUS_SERVER_PORT")

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "1502" // techplex/modbus-sim default port
	}

	t.Logf("testing Modbus connection config %s:%s", host, port)

	// Verify environment variable setup
	assert.NotEqual(t, "", host)
	assert.NotEqual(t, "", port)
	assert.Equal(t, "1502", port) // Verify correct port used
}

// TestModbusBasicOperations basic Modbus operation test framework
func TestModbusBasicOperations(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("Skipping Modbus basic operations test")
	}

	// Simulate test timeout protection
	timeout := time.After(10 * time.Second)
	done := make(chan bool)

	go func() {
		// Simulate some Modbus operations
		time.Sleep(200 * time.Millisecond)
		t.Log("Modbus basic operations simulation completed")
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("Modbus basic operations test timeout")
	case <-done:
		t.Log("Modbus basic operations test completed")
	}
}

// TestModbusNodeOnMsgInvalidAddress verifies that invalid addresses are routed to Failure.
func TestModbusNodeOnMsgInvalidAddress(t *testing.T) {
	node := &ModbusNode{
		Config: ModbusConfiguration{
			Cmd:      "ReadCoils",
			Address:  "bad-address",
			Quantity: "1",
			UnitId:   1,
			Server:   "mock://modbus",
		},
	}
	err := node.SharedNode.InitWithClose(types.NewConfig(), node.Type(), "mock://modbus", false, func() (*modbus.ModbusClient, error) {
		return &modbus.ModbusClient{}, nil
	}, func(client *modbus.ModbusClient) error {
		return nil
	})
	assert.Nil(t, err)
	node.addressTemplate = str.NewTemplate(node.Config.Address)
	node.quantityTemplate = str.NewTemplate(node.Config.Quantity)
	node.valueTemplate = str.NewTemplate(node.Config.Value)
	node.regTypeTemplate = str.NewTemplate(node.Config.RegType)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for modbus invalid address callback")
	}
}

// TestModbusNodeOnMsgMissingClient verifies that missing clients are routed to Failure.
func TestModbusNodeOnMsgMissingClient(t *testing.T) {
	node := &ModbusNode{
		Config: ModbusConfiguration{
			Cmd:      "ReadCoils",
			Address:  "1",
			Quantity: "1",
			UnitId:   1,
		},
	}

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, base.ErrClientNotInit, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for modbus missing client callback")
	}
}

// TestModbusNodeInitSoftFail: 设备不可达时 Init 必须返回 nil(不阻塞链保存/加载),
// 连接由 SharedNode 冷却后懒重试。NodeClientInitNow=true 立即建连的场景。
func TestModbusNodeInitSoftFail(t *testing.T) {
	cfg := types.NewConfig()
	cfg.NodeClientInitNow = true
	node := &ModbusNode{}
	err := node.Init(cfg, types.Configuration{
		"server":  "tcp://127.0.0.1:1",
		"cmd":     "03",
		"address": "0",
	})
	assert.Nil(t, err, "Init 不应因设备不可达而失败")
	node.Destroy()
}
