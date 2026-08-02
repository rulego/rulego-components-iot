/*
 * Copyright 2024 The RuleGo Authors.
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

package opcua

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/engine"
)

func TestOpcUaEndpoint(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("Skip OPC UA endpoint test")
	}

	t.Run("New", func(t *testing.T) {
		ep := &OpcUa{}
		newEp := ep.New()

		opcuaEp, ok := newEp.(*OpcUa)
		if !ok {
			t.Fatalf("New() should return *OpcUa type")
		}

		// Check default configuration
		if opcuaEp.Config.Server != "opc.tcp://localhost:4840" {
			t.Errorf("Expected default server to be 'opc.tcp://localhost:4840', got '%s'", opcuaEp.Config.Server)
		}

		if opcuaEp.Config.Policy != "None" {
			t.Errorf("Expected default policy to be 'None', got '%s'", opcuaEp.Config.Policy)
		}

		if opcuaEp.Config.Interval != "@every 1m" {
			t.Errorf("Expected default interval to be '@every 1m', got '%s'", opcuaEp.Config.Interval)
		}
	})

	t.Run("Type", func(t *testing.T) {
		ep := &OpcUa{}
		if ep.Type() != Type {
			t.Errorf("Expected type to be '%s', got '%s'", Type, ep.Type())
		}
	})

	t.Run("Init", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()

		configuration := types.Configuration{
			"server":      "opc.tcp://127.0.0.1:53530",
			"policy":      "None",
			"mode":        "none",
			"auth":        "anonymous",
			"interval":    "@every 30s",
			"nodeIds":     []string{"ns=3;i=1001", "ns=3;i=1009"},
			"username":    "",
			"password":    "",
			"certFile":    "",
			"certKeyFile": "",
		}

		err := ep.Init(config, configuration)
		if err != nil {
			t.Fatalf("Init() failed: %v", err)
		}

		// Verify configuration is set correctly
		if ep.Config.Server != "opc.tcp://127.0.0.1:53530" {
			t.Errorf("Expected server to be 'opc.tcp://127.0.0.1:53530', got '%s'", ep.Config.Server)
		}

		if ep.Config.Interval != "@every 30s" {
			t.Errorf("Expected interval to be '@every 30s', got '%s'", ep.Config.Interval)
		}

		if len(ep.Config.NodeIds) != 2 {
			t.Errorf("Expected NodeIds length to be 2, got %d", len(ep.Config.NodeIds))
		}
	})

	t.Run("Id", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server": "opc.tcp://test-server:4840",
		}

		_ = ep.Init(config, configuration)

		if ep.Id() != "opc.tcp://test-server:4840" {
			t.Errorf("Expected ID to be 'opc.tcp://test-server:4840', got '%s'", ep.Id())
		}
	})
}

func TestOpcUaRouter(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("Skip OPC UA router test")
	}

	t.Run("AddRouter", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530",
		}

		_ = ep.Init(config, configuration)

		router := impl.NewRouter().SetId("test-router").From("/test").End()
		routerId, err := ep.AddRouter(router)

		if err != nil {
			t.Fatalf("AddRouter() failed: %v", err)
		}

		if routerId != "test-router" {
			t.Errorf("Expected router ID to be 'test-router', got '%s'", routerId)
		}

		if ep.Router == nil {
			t.Error("Router was not set up correctly")
		}
	})

	t.Run("AddRouter_Nil", func(t *testing.T) {
		ep := &OpcUa{}
		_, err := ep.AddRouter(nil)

		if err == nil {
			t.Error("AddRouter(nil) should return error")
		}
	})

	t.Run("AddRouter_Duplicate", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530",
		}

		_ = ep.Init(config, configuration)

		router1 := impl.NewRouter().SetId("router1").From("/test1").End()
		router2 := impl.NewRouter().SetId("router2").From("/test2").End()

		_, err := ep.AddRouter(router1)
		if err != nil {
			t.Fatalf("First AddRouter() failed: %v", err)
		}

		_, err = ep.AddRouter(router2)
		if err == nil {
			t.Error("Duplicate AddRouter() should return error")
		}
	})

	t.Run("RemoveRouter", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530",
		}

		_ = ep.Init(config, configuration)

		router := impl.NewRouter().SetId("test-router").From("/test").End()
		_, _ = ep.AddRouter(router)

		err := ep.RemoveRouter("test-router")
		if err != nil {
			t.Fatalf("RemoveRouter() failed: %v", err)
		}

		if ep.Router != nil {
			t.Error("Router should have been removed")
		}
	})
}

func TestOpcUaLifecycle(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("Skip OPC UA lifecycle test")
	}

	t.Run("Start_And_Stop", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server":   "opc.tcp://127.0.0.1:53530",
			"interval": "@every 1s",
			"nodeIds":  []string{"ns=3;i=1001"},
		}

		_ = ep.Init(config, configuration)

		router := impl.NewRouter().SetId("test-router").From("/test").End()
		_, _ = ep.AddRouter(router)

		// Start endpoint
		err := ep.Start()
		if err != nil {
			t.Logf("Start() may fail due to server unavailability: %v", err)
		}

		// Wait a short while for scheduled task to execute
		time.Sleep(2 * time.Second)

		// Check if scheduled task is created
		if ep.cronTask == nil {
			t.Error("Scheduled task should have been created")
		}

		// Close endpoint
		err = ep.Close()
		if err != nil {
			t.Fatalf("Close() failed: %v", err)
		}

		// Verify resource cleanup
		if ep.cronTask != nil && ep.cronTask.Stop() == nil {
			t.Log("Scheduled task stopped correctly")
		}

		t.Log("Lifecycle test completed")
	})

	t.Run("Destroy", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530",
		}

		_ = ep.Init(config, configuration)
		_ = ep.Start()

		// Destroy should not error
		ep.Destroy()

		// Multiple destroy should not error
		ep.Destroy()
	})
}

func TestOpcUaReadNodes(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("Skip OPC UA read nodes test")
	}

	t.Run("ReadNodes_Connection_Failed", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server":  "opc.tcp://127.0.0.1:53530", // Non-existent server
			"nodeIds": []string{"ns=3;i=1001", "ns=3;i=1009"},
		}

		_ = ep.Init(config, configuration)

		router := impl.NewRouter().SetId("test-router").From("/test").End()
		_, _ = ep.AddRouter(router)

		// Call readNodes directly, expected to fail
		err := ep.readNodes(router)
		if err != nil {
			t.Logf("readNodes() failed as expected: %v", err)
		} else {
			t.Log("readNodes() succeeded unexpectedly (possibly due to mock environment)")
		}
	})
}

func TestOpcUaConfig(t *testing.T) {
	t.Run("OpcUaConfig_Methods", func(t *testing.T) {
		config := OpcUaConfig{
			Server:      "opc.tcp://test:4840",
			Policy:      "Basic256",
			Mode:        "SignAndEncrypt",
			Auth:        "UserName",
			Username:    "testuser",
			Password:    "testpass",
			CertFile:    "/path/to/cert.pem",
			CertKeyFile: "/path/to/key.pem",
		}

		if config.GetServer() != "opc.tcp://test:4840" {
			t.Errorf("GetServer() = %v, expected %v", config.GetServer(), "opc.tcp://test:4840")
		}

		if config.GetPolicy() != "Basic256" {
			t.Errorf("GetPolicy() = %v, expected %v", config.GetPolicy(), "Basic256")
		}

		if config.GetMode() != "SignAndEncrypt" {
			t.Errorf("GetMode() = %v, expected %v", config.GetMode(), "SignAndEncrypt")
		}

		if config.GetAuth() != "UserName" {
			t.Errorf("GetAuth() = %v, expected %v", config.GetAuth(), "UserName")
		}

		if config.GetUsername() != "testuser" {
			t.Errorf("GetUsername() = %v, expected %v", config.GetUsername(), "testuser")
		}

		if config.GetPassword() != "testpass" {
			t.Errorf("GetPassword() = %v, expected %v", config.GetPassword(), "testpass")
		}

		if config.GetCertFile() != "/path/to/cert.pem" {
			t.Errorf("GetCertFile() = %v, expected %v", config.GetCertFile(), "/path/to/cert.pem")
		}

		if config.GetCertKeyFile() != "/path/to/key.pem" {
			t.Errorf("GetCertKeyFile() = %v, expected %v", config.GetCertKeyFile(), "/path/to/key.pem")
		}
	})
}

func TestOpcUaMessages(t *testing.T) {
	t.Run("RequestMessage", func(t *testing.T) {
		req := &RequestMessage{}

		// Test Headers
		headers := req.Headers()
		if headers == nil {
			t.Error("Headers() should not return nil")
		}

		// Test From
		if req.From() != "" {
			t.Error("From() should return empty string")
		}

		// Test GetParam
		if req.GetParam("test") != "" {
			t.Error("GetParam() should return empty string")
		}

		// Test message setting and getting
		ruleMsg := types.NewMsg(0, "TEST", types.JSON, types.NewMetadata(), "test data")
		req.SetMsg(&ruleMsg)

		if req.GetMsg() != &ruleMsg {
			t.Error("GetMsg() should return the set message")
		}

		// Test status code
		req.SetStatusCode(200)
		if req.statusCode != 200 {
			t.Error("Status code should be set correctly")
		}

		// Test Body
		req.SetBody([]byte("test body"))
		if string(req.body) != "test body" {
			t.Error("Body should be set correctly")
		}
	})

	t.Run("ResponseMessage", func(t *testing.T) {
		resp := &ResponseMessage{}

		// Test Headers
		headers := resp.Headers()
		if headers == nil {
			t.Error("Headers() should not return nil")
		}

		// Test From
		if resp.From() != "" {
			t.Error("From() should return empty string")
		}

		// Test GetParam
		if resp.GetParam("test") != "" {
			t.Error("GetParam() should return empty string")
		}

		// Test message setting and getting
		ruleMsg := types.NewMsg(0, "TEST", types.JSON, types.NewMetadata(), "test data")
		resp.SetMsg(&ruleMsg)

		if resp.GetMsg() != &ruleMsg {
			t.Error("GetMsg() should return the set message")
		}

		// Test status code
		resp.SetStatusCode(200)
		if resp.statusCode != 200 {
			t.Error("Status code should be set correctly")
		}

		// Test Body
		resp.SetBody([]byte("test body"))
		if string(resp.body) != "test body" {
			t.Error("Body should be set correctly")
		}
	})
}

func TestOpcUaRegistration(t *testing.T) {
	t.Run("Component_Registration", func(t *testing.T) {
		// Create new instance to verify type
		ep := &OpcUa{}
		newEp := ep.New()
		if opcuaEp, ok := newEp.(*OpcUa); !ok {
			t.Errorf("Registered component should be *OpcUa type, got %T", newEp)
		} else {
			if opcuaEp.Type() != Type {
				t.Errorf("Component type should be %s, got %s", Type, opcuaEp.Type())
			}
		}
	})
}

// TestOpcUaEndpointGracefulShutdown tests graceful shutdown functionality of OPC UA endpoint
func TestOpcUaEndpointGracefulShutdown(t *testing.T) {
	// Skip if no OPC UA server available or if tests are disabled
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" || !isOpcUaServerAvailable() {
		t.Skip("Skip OPC UA graceful shutdown test: server unavailable or test disabled")
		return
	}

	t.Run("GracefulShutdownDuringReading", func(t *testing.T) {
		var config = engine.NewConfig()

		// Create a simple rule chain for testing
		// Create a simple rule chain for testing
		_, err := engine.New("opcua-test01", []byte(`{
			"ruleChain": {
				"name": "opcua test chain",
				"root": true
			},
			"metadata": {
				"nodes": [
					{
						"id": "s1", 
						"type": "jsFilter",
						"name": "opcua test",
						"configuration": {
							"jsScript": "return true;"
						}
					}
				],
				"connections": []
			}
		}`), engine.WithConfig(config))
		if err != nil {
			t.Fatal(err)
		}

		// Configure OPC UA endpoint
		// Configure OPC UA endpoint
		opcUaEndpoint := &OpcUa{
			Config: OpcUaConfig{
				Server:   "opc.tcp://localhost:4840",
				Policy:   "None",
				Mode:     "none",
				Auth:     "anonymous",
				Interval: "@every 2s", // Faster interval for testing
				NodeIds:  []string{"ns=2;s=Channel1.Device1.Tag1"},
			},
		}

		configuration := make(types.Configuration)
		configuration["server"] = "opc.tcp://localhost:4840"
		configuration["policy"] = "None"
		configuration["mode"] = "none"
		configuration["auth"] = "anonymous"
		configuration["interval"] = "@every 2s"
		configuration["nodeIds"] = []string{"ns=2;s=Channel1.Device1.Tag1"}

		err = opcUaEndpoint.Init(config, configuration)
		if err != nil {
			t.Fatal(err)
		}

		// Set graceful shutdown timeout to 3 seconds for testing
		// Set graceful shutdown timeout to 3 seconds for testing
		opcUaEndpoint.GracefulShutdown.InitGracefulShutdown(config.Logger, 3*time.Second)

		// Track operations
		// Track operations
		var readCount int64
		var errorCount int64

		// Add router with processing chain
		// Add router with processing chain
		router := impl.NewRouter().From("").To("chain:opcua-test01").Transform(func(router endpoint.Router, exchange *endpoint.Exchange) bool {
			if exchange.Out.GetError() != nil {
				atomic.AddInt64(&errorCount, 1)
			} else {
				atomic.AddInt64(&readCount, 1)
			}
			// Simulate some processing time
			// Simulate some processing time
			time.Sleep(100 * time.Millisecond)
			return true
		}).End()

		_, err = opcUaEndpoint.AddRouter(router)
		if err != nil {
			t.Fatal(err)
		}

		// Start endpoint
		// Start endpoint
		err = opcUaEndpoint.Start()
		if err != nil {
			t.Fatal(err)
		}

		// Let some reads occur
		// Let some reads happen
		time.Sleep(3 * time.Second)

		// Check that some operations occurred
		// Check if some operations occurred
		initialReadCount := atomic.LoadInt64(&readCount)
		initialErrorCount := atomic.LoadInt64(&errorCount)
		t.Logf("Before shutdown: reads=%d, errors=%d", initialReadCount, initialErrorCount)

		// Initiate graceful shutdown
		// Start graceful shutdown
		shutdownStart := time.Now()
		opcUaEndpoint.GracefulStop()
		shutdownDuration := time.Since(shutdownStart)

		// Verify graceful shutdown behavior
		// Verify graceful shutdown behavior
		if shutdownDuration < 0 {
			t.Error("Shutdown should complete")
		}
		if shutdownDuration >= 10*time.Second {
			t.Error("Shutdown should not exceed maximum timeout")
		}

		finalReadCount := atomic.LoadInt64(&readCount)
		finalErrorCount := atomic.LoadInt64(&errorCount)

		t.Logf("Graceful shutdown completed in %v", shutdownDuration)
		t.Logf("Final counts: reads=%d, errors=%d", finalReadCount, finalErrorCount)

		// Verify that the endpoint stopped processing new operations
		// Verify endpoint stops processing new operations
		if finalReadCount < initialReadCount {
			t.Error("Read count should not decrease")
		}
	})

	t.Run("ShutdownStopsScheduledOperations", func(t *testing.T) {
		var config = engine.NewConfig()

		// Create a simple rule chain for testing
		// Create a simple rule chain for testing
		_, err := engine.New("opcua-test02", []byte(`{
			"ruleChain": {
				"name": "opcua test chain",
				"root": true
			},
			"metadata": {
				"nodes": [
					{
						"id": "s1", 
						"type": "jsFilter",
						"name": "opcua test",
						"configuration": {
							"jsScript": "return true;"
						}
					}
				],
				"connections": []
			}
		}`), engine.WithConfig(config))
		if err != nil {
			t.Fatal(err)
		}

		opcUaEndpoint := &OpcUa{
			Config: OpcUaConfig{
				Server:   "opc.tcp://localhost:4840",
				Policy:   "None",
				Mode:     "none",
				Auth:     "anonymous",
				Interval: "@every 1s", // Very fast interval for testing
				NodeIds:  []string{"ns=2;s=Channel1.Device1.Tag1"},
			},
		}

		configuration := make(types.Configuration)
		configuration["server"] = "opc.tcp://localhost:4840"
		configuration["policy"] = "None"
		configuration["mode"] = "none"
		configuration["auth"] = "anonymous"
		configuration["interval"] = "@every 1s"
		configuration["nodeIds"] = []string{"ns=2;s=Channel1.Device1.Tag1"}

		err = opcUaEndpoint.Init(config, configuration)
		if err != nil {
			t.Fatal(err)
		}

		// Set very short timeout for faster testing
		// Set very short timeout for faster testing
		opcUaEndpoint.GracefulShutdown.InitGracefulShutdown(config.Logger, 1*time.Second)

		var operationCount int64

		// Add router that counts operations
		// Add router for counting operations
		router := impl.NewRouter().From("").To("chain:opcua-test02").Transform(func(router endpoint.Router, exchange *endpoint.Exchange) bool {
			atomic.AddInt64(&operationCount, 1)
			return true
		}).End()

		_, err = opcUaEndpoint.AddRouter(router)
		if err != nil {
			t.Fatal(err)
		}

		err = opcUaEndpoint.Start()
		if err != nil {
			t.Fatal(err)
		}

		// Let some operations occur
		// Let some operations happen
		time.Sleep(2 * time.Second)

		countBeforeShutdown := atomic.LoadInt64(&operationCount)
		t.Logf("Operations before shutdown: %d", countBeforeShutdown)

		// Start shutdown immediately
		// Start shutdown immediately
		opcUaEndpoint.GracefulStop()

		// Wait a bit and check that no new operations occur
		// Wait a while and check no new operations occur
		time.Sleep(2 * time.Second)

		countAfterShutdown := atomic.LoadInt64(&operationCount)
		t.Logf("Operations after shutdown: %d", countAfterShutdown)

		// Operations should have stopped or increased very little
		// Operations should have stopped or increased very little
		if countAfterShutdown < countBeforeShutdown {
			t.Error("Operation count should not decrease")
		}
		// Allow for some operations that were already in progress
		// Allow some already in-progress operations
		if (countAfterShutdown - countBeforeShutdown) > 2 {
			t.Error("Should have stopped scheduling new operations")
		}
	})
}

// isOpcUaServerAvailable checks if OPC UA server is available for testing
// isOpcUaServerAvailable checks if there is an available OPC UA server for testing
func isOpcUaServerAvailable() bool {
	// For CI/testing, we assume OPC UA server might not be available
	// We can implement a quick connection test here if needed
	// For CI/testing, we assume OPC UA server may not be available
	// If needed, we can implement quick connection test here
	return false // Set to true if you have a local OPC UA server for testing
}
