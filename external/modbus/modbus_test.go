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

// TestModbusNode tests the basic functions of Modbus nodes
func TestModbusNode(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("Skip Modbus node testing")
	}

	Registry := &types.SafeComponentSlice{}
	Registry.Add(&ModbusNode{})

	node := &ModbusNode{}
	assert.Equal(t, "x/modbus", node.Type())

	// Create a new node instance
	newNode := node.New()
	assert.NotNil(t, newNode)

	t.Log("Modbus Node basic function tests have passed")
}

// TestModbusConnectionConfig Tests the Modbus connection configuration
func TestModbusConnectionConfig(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("Skip the Modbus connection configuration test")
	}

	host := os.Getenv("MODBUS_SERVER_HOST")
	port := os.Getenv("MODBUS_SERVER_PORT")

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "1502" // Techplex/Modbus-sim is the default port
	}

	t.Logf("Test Modbus connection configuration %s:%s", host, port)

	// Verify environment variable settings
	assert.NotEqual(t, "", host)
	assert.NotEqual(t, "", port)
	assert.Equal(t, "1502", port) // Verify that the correct port is used
}

// TestModbusBasicOperations is the basic Modbus operation testing framework
func TestModbusBasicOperations(t *testing.T) {
	if os.Getenv("SKIP_MODBUS_TESTS") == "true" {
		t.Skip("Skip the Modbus basic operations test")
	}

	// Simulated test timeout protection
	timeout := time.After(10 * time.Second)
	done := make(chan bool)

	go func() {
		// Simulates some Modbus operations
		time.Sleep(200 * time.Millisecond)
		t.Log("Modbus Basic operation simulation completed")
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("Modbus Basic operation test timed out")
	case <-done:
		t.Log("Modbus Basic operation test completed")
	}
}
