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
		t.Skip("跳过 OPC UA 端点测试")
	}

	t.Run("New", func(t *testing.T) {
		ep := &OpcUa{}
		newEp := ep.New()

		opcuaEp, ok := newEp.(*OpcUa)
		if !ok {
			t.Fatalf("New() 应该返回 *OpcUa 类型")
		}

		// 检查默认配置
		if opcuaEp.Config.Server != "opc.tcp://localhost:4840" {
			t.Errorf("期望默认服务器为 'opc.tcp://localhost:4840', 实际为 '%s'", opcuaEp.Config.Server)
		}

		if opcuaEp.Config.Policy != "None" {
			t.Errorf("期望默认策略为 'None', 实际为 '%s'", opcuaEp.Config.Policy)
		}

		if opcuaEp.Config.Interval != "@every 1m" {
			t.Errorf("期望默认间隔为 '@every 1m', 实际为 '%s'", opcuaEp.Config.Interval)
		}
	})

	t.Run("Type", func(t *testing.T) {
		ep := &OpcUa{}
		if ep.Type() != Type {
			t.Errorf("期望类型为 '%s', 实际为 '%s'", Type, ep.Type())
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
			t.Fatalf("Init() 失败: %v", err)
		}

		// 验证配置是否正确设置
		if ep.Config.Server != "opc.tcp://127.0.0.1:53530" {
			t.Errorf("期望服务器为 'opc.tcp://127.0.0.1:53530', 实际为 '%s'", ep.Config.Server)
		}

		if ep.Config.Interval != "@every 30s" {
			t.Errorf("期望间隔为 '@every 30s', 实际为 '%s'", ep.Config.Interval)
		}

		if len(ep.Config.NodeIds) != 2 {
			t.Errorf("期望 NodeIds 长度为 2, 实际为 %d", len(ep.Config.NodeIds))
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
			t.Errorf("期望 ID 为 'opc.tcp://test-server:4840', 实际为 '%s'", ep.Id())
		}
	})
}

func TestOpcUaRouter(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("跳过 OPC UA 路由器测试")
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
			t.Fatalf("AddRouter() 失败: %v", err)
		}

		if routerId != "test-router" {
			t.Errorf("期望路由器 ID 为 'test-router', 实际为 '%s'", routerId)
		}

		if ep.Router == nil {
			t.Error("路由器未正确设置")
		}
	})

	t.Run("AddRouter_Nil", func(t *testing.T) {
		ep := &OpcUa{}
		_, err := ep.AddRouter(nil)

		if err == nil {
			t.Error("AddRouter(nil) 应该返回错误")
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
			t.Fatalf("第一个 AddRouter() 失败: %v", err)
		}

		_, err = ep.AddRouter(router2)
		if err == nil {
			t.Error("重复 AddRouter() 应该返回错误")
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
			t.Fatalf("RemoveRouter() 失败: %v", err)
		}

		if ep.Router != nil {
			t.Error("路由器应该被移除")
		}
	})
}

func TestOpcUaLifecycle(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("跳过 OPC UA 生命周期测试")
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

		// 启动端点
		err := ep.Start()
		if err != nil {
			t.Logf("Start() 可能因为服务器不可用而失败: %v", err)
		}

		// 等待一小段时间让定时任务有机会执行
		time.Sleep(2 * time.Second)

		// 检查定时任务是否创建
		if ep.cronTask == nil {
			t.Error("定时任务应该被创建")
		}

		// 关闭端点
		err = ep.Close()
		if err != nil {
			t.Fatalf("Close() 失败: %v", err)
		}

		// 验证资源清理
		if ep.cronTask != nil && ep.cronTask.Stop() == nil {
			t.Log("定时任务已正确停止")
		}

		t.Log("生命周期测试完成")
	})

	t.Run("Destroy", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530",
		}

		_ = ep.Init(config, configuration)
		_ = ep.Start()

		// 销毁不应该报错
		ep.Destroy()

		// 多次销毁也不应该报错
		ep.Destroy()
	})
}

func TestOpcUaReadNodes(t *testing.T) {
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" {
		t.Skip("跳过 OPC UA 读取节点测试")
	}

	t.Run("ReadNodes_Connection_Failed", func(t *testing.T) {
		ep := &OpcUa{}
		config := engine.NewConfig()
		configuration := types.Configuration{
			"server":  "opc.tcp://127.0.0.1:53530", // 不存在的服务器
			"nodeIds": []string{"ns=3;i=1001", "ns=3;i=1009"},
		}

		_ = ep.Init(config, configuration)

		router := impl.NewRouter().SetId("test-router").From("/test").End()
		_, _ = ep.AddRouter(router)

		// 直接调用 readNodes，预期会失败
		err := ep.readNodes(router)
		if err != nil {
			t.Logf("readNodes() 如预期失败: %v", err)
		} else {
			t.Log("readNodes() 意外成功（可能因为模拟环境）")
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
			t.Errorf("GetServer() = %v, 期望 %v", config.GetServer(), "opc.tcp://test:4840")
		}

		if config.GetPolicy() != "Basic256" {
			t.Errorf("GetPolicy() = %v, 期望 %v", config.GetPolicy(), "Basic256")
		}

		if config.GetMode() != "SignAndEncrypt" {
			t.Errorf("GetMode() = %v, 期望 %v", config.GetMode(), "SignAndEncrypt")
		}

		if config.GetAuth() != "UserName" {
			t.Errorf("GetAuth() = %v, 期望 %v", config.GetAuth(), "UserName")
		}

		if config.GetUsername() != "testuser" {
			t.Errorf("GetUsername() = %v, 期望 %v", config.GetUsername(), "testuser")
		}

		if config.GetPassword() != "testpass" {
			t.Errorf("GetPassword() = %v, 期望 %v", config.GetPassword(), "testpass")
		}

		if config.GetCertFile() != "/path/to/cert.pem" {
			t.Errorf("GetCertFile() = %v, 期望 %v", config.GetCertFile(), "/path/to/cert.pem")
		}

		if config.GetCertKeyFile() != "/path/to/key.pem" {
			t.Errorf("GetCertKeyFile() = %v, 期望 %v", config.GetCertKeyFile(), "/path/to/key.pem")
		}
	})
}

func TestOpcUaMessages(t *testing.T) {
	t.Run("RequestMessage", func(t *testing.T) {
		req := &RequestMessage{}

		// 测试 Headers
		headers := req.Headers()
		if headers == nil {
			t.Error("Headers() 不应该返回 nil")
		}

		// 测试 From
		if req.From() != "" {
			t.Error("From() 应该返回空字符串")
		}

		// 测试 GetParam
		if req.GetParam("test") != "" {
			t.Error("GetParam() 应该返回空字符串")
		}

		// 测试消息设置和获取
		ruleMsg := types.NewMsg(0, "TEST", types.JSON, types.NewMetadata(), "test data")
		req.SetMsg(&ruleMsg)

		if req.GetMsg() != &ruleMsg {
			t.Error("GetMsg() 应该返回设置的消息")
		}

		// 测试状态码
		req.SetStatusCode(200)
		if req.statusCode != 200 {
			t.Error("状态码应该被正确设置")
		}

		// 测试 Body
		req.SetBody([]byte("test body"))
		if string(req.body) != "test body" {
			t.Error("Body 应该被正确设置")
		}
	})

	t.Run("ResponseMessage", func(t *testing.T) {
		resp := &ResponseMessage{}

		// 测试 Headers
		headers := resp.Headers()
		if headers == nil {
			t.Error("Headers() 不应该返回 nil")
		}

		// 测试 From
		if resp.From() != "" {
			t.Error("From() 应该返回空字符串")
		}

		// 测试 GetParam
		if resp.GetParam("test") != "" {
			t.Error("GetParam() 应该返回空字符串")
		}

		// 测试消息设置和获取
		ruleMsg := types.NewMsg(0, "TEST", types.JSON, types.NewMetadata(), "test data")
		resp.SetMsg(&ruleMsg)

		if resp.GetMsg() != &ruleMsg {
			t.Error("GetMsg() 应该返回设置的消息")
		}

		// 测试状态码
		resp.SetStatusCode(200)
		if resp.statusCode != 200 {
			t.Error("状态码应该被正确设置")
		}

		// 测试 Body
		resp.SetBody([]byte("test body"))
		if string(resp.body) != "test body" {
			t.Error("Body 应该被正确设置")
		}
	})
}

func TestOpcUaRegistration(t *testing.T) {
	t.Run("Component_Registration", func(t *testing.T) {
		// 创建新实例来验证类型
		ep := &OpcUa{}
		newEp := ep.New()
		if opcuaEp, ok := newEp.(*OpcUa); !ok {
			t.Errorf("注册的组件应该是 *OpcUa 类型，实际为 %T", newEp)
		} else {
			if opcuaEp.Type() != Type {
				t.Errorf("组件类型应该为 %s，实际为 %s", Type, opcuaEp.Type())
			}
		}
	})
}

// TestOpcUaEndpointGracefulShutdown tests graceful shutdown functionality of OPC UA endpoint
// TestOpcUaEndpointGracefulShutdown 测试 OPC UA 端点的优雅停机功能
func TestOpcUaEndpointGracefulShutdown(t *testing.T) {
	// Skip if no OPC UA server available or if tests are disabled
	// 如果没有可用的 OPC UA 服务器或测试被禁用则跳过
	if os.Getenv("SKIP_OPCUA_TESTS") == "true" || !isOpcUaServerAvailable() {
		t.Skip("跳过 OPC UA 优雅停机测试：服务器不可用或测试被禁用")
		return
	}

	t.Run("GracefulShutdownDuringReading", func(t *testing.T) {
		var config = engine.NewConfig()

		// Create a simple rule chain for testing
		// 创建一个简单的规则链用于测试
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
		// 配置 OPC UA 端点
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
		// 设置优雅停机超时为3秒用于测试
		opcUaEndpoint.GracefulShutdown.InitGracefulShutdown(config.Logger, 3*time.Second)

		// Track operations
		// 跟踪操作
		var readCount int64
		var errorCount int64

		// Add router with processing chain
		// 添加带有处理链的路由器
		router := impl.NewRouter().From("").To("chain:opcua-test01").Transform(func(router endpoint.Router, exchange *endpoint.Exchange) bool {
			if exchange.Out.GetError() != nil {
				atomic.AddInt64(&errorCount, 1)
			} else {
				atomic.AddInt64(&readCount, 1)
			}
			// Simulate some processing time
			// 模拟一些处理时间
			time.Sleep(100 * time.Millisecond)
			return true
		}).End()

		_, err = opcUaEndpoint.AddRouter(router)
		if err != nil {
			t.Fatal(err)
		}

		// Start endpoint
		// 启动端点
		err = opcUaEndpoint.Start()
		if err != nil {
			t.Fatal(err)
		}

		// Let some reads occur
		// 让一些读取发生
		time.Sleep(3 * time.Second)

		// Check that some operations occurred
		// 检查是否发生了一些操作
		initialReadCount := atomic.LoadInt64(&readCount)
		initialErrorCount := atomic.LoadInt64(&errorCount)
		t.Logf("Before shutdown: reads=%d, errors=%d", initialReadCount, initialErrorCount)

		// Initiate graceful shutdown
		// 启动优雅停机
		shutdownStart := time.Now()
		opcUaEndpoint.GracefulStop()
		shutdownDuration := time.Since(shutdownStart)

		// Verify graceful shutdown behavior
		// 验证优雅停机行为
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
		// 验证端点停止处理新操作
		if finalReadCount < initialReadCount {
			t.Error("Read count should not decrease")
		}
	})

	t.Run("ShutdownStopsScheduledOperations", func(t *testing.T) {
		var config = engine.NewConfig()

		// Create a simple rule chain for testing
		// 创建一个简单的规则链用于测试
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
		// 设置很短的超时时间以便更快测试
		opcUaEndpoint.GracefulShutdown.InitGracefulShutdown(config.Logger, 1*time.Second)

		var operationCount int64

		// Add router that counts operations
		// 添加计算操作的路由器
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
		// 让一些操作发生
		time.Sleep(2 * time.Second)

		countBeforeShutdown := atomic.LoadInt64(&operationCount)
		t.Logf("Operations before shutdown: %d", countBeforeShutdown)

		// Start shutdown immediately
		// 立即开始停机
		opcUaEndpoint.GracefulStop()

		// Wait a bit and check that no new operations occur
		// 等待一会儿并检查没有新操作发生
		time.Sleep(2 * time.Second)

		countAfterShutdown := atomic.LoadInt64(&operationCount)
		t.Logf("Operations after shutdown: %d", countAfterShutdown)

		// Operations should have stopped or increased very little
		// 操作应该已经停止或增加很少
		if countAfterShutdown < countBeforeShutdown {
			t.Error("Operation count should not decrease")
		}
		// Allow for some operations that were already in progress
		// 允许一些已经在进行中的操作
		if (countAfterShutdown - countBeforeShutdown) > 2 {
			t.Error("Should have stopped scheduling new operations")
		}
	})
}

// isOpcUaServerAvailable checks if OPC UA server is available for testing
// isOpcUaServerAvailable 检查是否有可用的 OPC UA 服务器进行测试
func isOpcUaServerAvailable() bool {
	// For CI/testing, we assume OPC UA server might not be available
	// We can implement a quick connection test here if needed
	// 对于 CI/测试，我们假设 OPC UA 服务器可能不可用
	// 如果需要，我们可以在这里实现快速连接测试
	return false // Set to true if you have a local OPC UA server for testing
}
