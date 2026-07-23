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
		t.Skip("Skip OPC UA endpoint testing")
	}

	t.Run("New", func(t *testing.T) {
		ep := &OpcUa{}
		newEp := ep.New()

		opcuaEp, ok := newEp.(*OpcUa)
		if !ok {
			t.Fatalf("New() should return a *OpcUa type")
		}

		// Check the default configuration
		if opcuaEp.Config.Server != "opc.tcp://localhost:4840" {
			t.Errorf("Expect the default server to be 'opc.tcp://localhost:4840', but actually '%s'", opcuaEp.Config.Server)
		}

		if opcuaEp.Config.Policy != "None" {
			t.Errorf("The default policy is expected to be 'None', but the actual policy is '%s'", opcuaEp.Config.Policy)
		}

		if opcuaEp.Config.Interval != "@every 1m" {
			t.Errorf("The expected default spacing is '@every 1m', but the actual interval is '%s'", opcuaEp.Config.Interval)
		}
	})

	t.Run("Type", func(t *testing.T) {
		ep := &OpcUa{}
		if ep.Type() != Type {
			t.Errorf("The expected type is '%s', but the actual type is '%s'", Type, ep.Type())
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
			t.Fatalf("Init() Failure: %v", err)
		}

		// Verify that the configuration is set correctly
		if ep.Config.Server != "opc.tcp://127.0.0.1:53530" {
			t.Errorf("Expected server is 'opc.tcp://127.0.0.1:53530', actual is '%s'", ep.Config.Server)
		}

		if ep.Config.Interval != "@every 30s" {
			t.Errorf("The expected interval is '@every 30s', but the actual interval is '%s'", ep.Config.Interval)
		}

		if len(ep.Config.NodeIds) != 2 {
			t.Errorf("The expected NodeIds length is 2, but the actual length is %d", len(ep.Config.NodeIds))
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
			t.Errorf("Expected ID is 'opc.tcp://test-server:4840', actual is '%s'", ep.Id())
		}
	})
}

func TestOpcUaRouter(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("Skip OPC UA router testing")
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
			t.Fatalf("AddRouter() Failure: %v", err)
		}

		if routerId != "test-router" {
			t.Errorf("The router ID is expected to be 'test-router', but the actual value is '%s'", routerId)
		}

		if ep.Router == nil {
			t.Error("The router is not properly configured")
		}
	})

	t.Run("AddRouter_Nil", func(t *testing.T) {
		ep := &OpcUa{}
		_, err := ep.AddRouter(nil)

		if err == nil {
			t.Error("AddRouter(nil) should return an error")
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
			t.Fatalf("First AddRouter() failure: %v", err)
		}

		_, err = ep.AddRouter(router2)
		if err == nil {
			t.Error("Repeating AddRouter() should return an error")
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
			t.Fatalf("RemoveRouter() Failure: %v", err)
		}

		if ep.Router != nil {
			t.Error("The router should be removed")
		}
	})
}

func TestOpcUaLifecycle(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("Skip OPC UA lifecycle testing")
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

		// Start the endpoint
		err := ep.Start()
		if err != nil {
			t.Logf("Start() may fail because the server is unavailable: %v", err)
		}

		// Wait a short period for a chance to execute the scheduled task
		time.Sleep(2 * time.Second)

		// Check if a scheduled task has been created
		if ep.cronTask == nil {
			t.Error("Timed tasks should be created")
		}

		// Shut down the endpoint
		err = ep.Close()
		if err != nil {
			t.Fatalf("Close() Failure: %v", err)
		}

		// Verify resource cleanup
		if ep.cronTask != nil && ep.cronTask.Stop() == nil {
			t.Log("The scheduled task has been properly stopped")
		}

		t.Log("Lifecycle testing completed")
	})

	t.Run("Destroy", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530",
		}

		_ = ep.Init(config, configuration)
		_ = ep.Start()

		// Destruction should not be reported in error
		ep.Destroy()

		// Multiple burns should not be reported incorrectly
		ep.Destroy()
	})
}

func TestOpcUaReadNodes(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("Skip OPC UA read node tests")
	}

	t.Run("ReadNodes_Connection_Failed", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server":  "opc.tcp://127.0.0.1:53530", // A server that doesn't exist
			"nodeIds": []string{"ns=3;i=1001", "ns=3;i=1009"},
		}

		_ = ep.Init(config, configuration)

		router := impl.NewRouter().SetId("test-router").From("/test").End()
		_, _ = ep.AddRouter(router)

		// Directly calling readNodes is expected to fail
		err := ep.readNodes(router)
		if err != nil {
			t.Logf("readNodes() Failure as expected: %v", err)
		} else {
			t.Log("readNodes() Unexpected success (possibly due to simulated environment)")
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
			t.Error("From() should return an empty string")
		}

		// Test GetParam
		if req.GetParam("test") != "" {
			t.Error("GetParam() should return an empty string")
		}

		// Test message settings and acquisition
		ruleMsg := types.NewMsg(0, "TEST", types.JSON, types.NewMetadata(), "test data")
		req.SetMsg(&ruleMsg)

		if req.GetMsg() != &ruleMsg {
			t.Error("GetMsg() should return the message set up")
		}

		// Test status code
		req.SetStatusCode(200)
		if req.statusCode != 200 {
			t.Error("The status code should be set correctly")
		}

		// Test the body
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
			t.Error("From() should return an empty string")
		}

		// Test GetParam
		if resp.GetParam("test") != "" {
			t.Error("GetParam() should return an empty string")
		}

		// Test message settings and acquisition
		ruleMsg := types.NewMsg(0, "TEST", types.JSON, types.NewMetadata(), "test data")
		resp.SetMsg(&ruleMsg)

		if resp.GetMsg() != &ruleMsg {
			t.Error("GetMsg() should return the message set up")
		}

		// Test status code
		resp.SetStatusCode(200)
		if resp.statusCode != 200 {
			t.Error("The status code should be set correctly")
		}

		// Test the body
		resp.SetBody([]byte("test body"))
		if string(resp.body) != "test body" {
			t.Error("Body should be set correctly")
		}
	})
}

func TestOpcUaRegistration(t *testing.T) {
	t.Run("Component_Registration", func(t *testing.T) {
		// Create a new instance to validate the type
		ep := &OpcUa{}
		newEp := ep.New()
		if opcuaEp, ok := newEp.(*OpcUa); !ok {
			t.Errorf("The registered component should be of type *OpcUa, which is actually %T", newEp)
		} else {
			if opcuaEp.Type() != Type {
				t.Errorf("The component type should be %s, but the actual number is %s", Type, opcuaEp.Type())
			}
		}
	})
}

// TestOpcUaEndpointGracefulShutdown tests graceful shutdown functionality of OPC UA endpoint
// TestOpcUaEndpointGracefulShutdown Tests the graceful shutdown feature of OPC UA endpoints
func TestOpcUaEndpointGracefulShutdown(t *testing.T) {
	// Skip if no OPC UA server available or if tests are disabled
	// If no OPC UA server is available or the test is disabled, skip it
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" || !isOpcUaServerAvailable() {
		t.Skip("Skip OPC UA Elegant Downtime Testing: Server unavailable or test disabled")
		return
	}

	t.Run("GracefulShutdownDuringReading", func(t *testing.T) {
		var config = engine.NewConfig()

		// Create a simple rule chain for testing
		// Create a simple chain of rules for testing
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
		// Configure the OPC UA endpoint
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
		// Set the elegant shutdown timeout to 3 seconds for testing
		opcUaEndpoint.GracefulShutdown.InitGracefulShutdown(config.Logger, 3*time.Second)

		// Track operations
		// Tracking operations
		var readCount int64
		var errorCount int64

		// Add router with processing chain
		// Add a router with a processing chain
		router := impl.NewRouter().From("").To("chain:opcua-test01").Transform(func(router endpoint.Router, exchange *endpoint.Exchange) bool {
			if exchange.Out.GetError() != nil {
				atomic.AddInt64(&errorCount, 1)
			} else {
				atomic.AddInt64(&readCount, 1)
			}
			// Simulate some processing time
			// Simulate some processing times
			time.Sleep(100 * time.Millisecond)
			return true
		}).End()

		_, err = opcUaEndpoint.AddRouter(router)
		if err != nil {
			t.Fatal(err)
		}

		// Start endpoint
		// Start the endpoint
		err = opcUaEndpoint.Start()
		if err != nil {
			t.Fatal(err)
		}

		// Let some reads occur
		// Let some readings happen
		time.Sleep(3 * time.Second)

		// Check that some operations occurred
		// Check if any operations have occurred
		initialReadCount := atomic.LoadInt64(&readCount)
		initialErrorCount := atomic.LoadInt64(&errorCount)
		t.Logf("Before shutdown: reads=%d, errors=%d", initialReadCount, initialErrorCount)

		// Initiate graceful shutdown
		// Launch with elegant stop
		shutdownStart := time.Now()
		opcUaEndpoint.GracefulStop()
		shutdownDuration := time.Since(shutdownStart)

		// Verify graceful shutdown behavior
		// Verify elegant downtime behavior
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
		// The verification endpoint stops processing new operations
		if finalReadCount < initialReadCount {
			t.Error("Read count should not decrease")
		}
	})

	t.Run("ShutdownStopsScheduledOperations", func(t *testing.T) {
		var config = engine.NewConfig()

		// Create a simple rule chain for testing
		// Create a simple chain of rules for testing
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
		// Set a very short timeout to enable faster testing
		opcUaEndpoint.GracefulShutdown.InitGracefulShutdown(config.Logger, 1*time.Second)

		var operationCount int64

		// Add router that counts operations
		// Add a router for computing operations
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
		// Immediately start shutting down
		opcUaEndpoint.GracefulStop()

		// Wait a bit and check that no new operations occur
		// Wait a moment and check if no new operations have occurred
		time.Sleep(2 * time.Second)

		countAfterShutdown := atomic.LoadInt64(&operationCount)
		t.Logf("Operations after shutdown: %d", countAfterShutdown)

		// Operations should have stopped or increased very little
		// Operations should have stopped or increased minimally
		if countAfterShutdown < countBeforeShutdown {
			t.Error("Operation count should not decrease")
		}
		// Allow for some operations that were already in progress
		// Allow for some operations that are already in progress
		if (countAfterShutdown - countBeforeShutdown) > 2 {
			t.Error("Should have stopped scheduling new operations")
		}
	})
}

// isOpcUaServerAvailable checks if OPC UA server is available for testing
// isOpcUaServerAvailable checks whether an available OPC UA server is available for testing
func isOpcUaServerAvailable() bool {
	// For CI/testing, we assume OPC UA server might not be available
	// We can implement a quick connection test here if needed
	// For CI/testing, we assume the OPC UA server may be unavailable
	// If needed, we can conduct quick connection tests here
	return false // Set to true if you have a local OPC UA server for testing
}
