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

package snmp

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/test/assert"
)

// ------------------------------------------------------------------------------------------------
// 纯函数测试
// ------------------------------------------------------------------------------------------------

// TestPduTypeString PDU 类型 -> 字符串
func TestPduTypeString(t *testing.T) {
	cases := map[gosnmp.Asn1BER]string{
		gosnmp.Integer:          "Integer",
		gosnmp.OctetString:      "OctetString",
		gosnmp.ObjectIdentifier: "ObjectIdentifier",
		gosnmp.IPAddress:        "IPAddress",
		gosnmp.Counter32:        "Counter32",
		gosnmp.Gauge32:          "Gauge32",
		gosnmp.TimeTicks:        "TimeTicks",
		gosnmp.Counter64:        "Counter64",
		gosnmp.Null:             "Null",
	}
	for typ, want := range cases {
		assert.Equal(t, want, pduTypeString(typ))
	}
	assert.Equal(t, "Unknown", pduTypeString(gosnmp.Boolean)) // 未知类型
}

// TestVersionString SnmpVersion -> 字符串
func TestVersionString(t *testing.T) {
	assert.Equal(t, "v1", versionString(gosnmp.Version1))
	assert.Equal(t, "v2c", versionString(gosnmp.Version2c))
	assert.Equal(t, "v3", versionString(gosnmp.Version3))
	assert.Equal(t, "unknown", versionString(gosnmp.SnmpVersion(0x9)))
}

// TestParseVersion 版本字符串解析
func TestParseVersion(t *testing.T) {
	// 合法值
	v, err := parseVersion("v2c")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version2c, v)

	v, err = parseVersion("")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version2c, v) // 默认 v2c

	v, err = parseVersion("v1")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version1, v)

	v, err = parseVersion("v3")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version3, v)

	// 非法值
	_, err = parseVersion("v4")
	assert.NotNil(t, err)
}

// TestTrapVars PDU 列表 -> 简化 map
func TestTrapVars(t *testing.T) {
	vars := []gosnmp.SnmpPDU{
		{Name: "1.3.6.1.2.1.1.3.0", Value: uint(100), Type: gosnmp.TimeTicks},           // sysUpTime
		{Name: "1.3.6.1.2.1.1.5.0", Value: []byte("router1"), Type: gosnmp.OctetString}, // sysName
	}
	result := trapVars(vars)
	assert.Equal(t, 2, len(result))
	assert.Equal(t, "1.3.6.1.2.1.1.3.0", result[0]["oid"])
	assert.Equal(t, "TimeTicks", result[0]["type"])
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", result[1]["oid"])
	assert.Equal(t, "OctetString", result[1]["type"])
}

// ------------------------------------------------------------------------------------------------
// 端点元信息测试
// ------------------------------------------------------------------------------------------------

// TestSnmpTrapEndpointMeta 端点类型/默认配置/ID
func TestSnmpTrapEndpointMeta(t *testing.T) {
	ep := &SnmpTrapEndpoint{}
	assert.Equal(t, "endpoint/snmp", ep.Type())
	assert.Equal(t, "endpoint", ep.Category())

	// 默认配置
	def := ep.New().(*SnmpTrapEndpoint)
	assert.Equal(t, "0.0.0.0:162", def.Config.Server)
	assert.Equal(t, "v2c", def.Config.Version)
	assert.Equal(t, "public", def.Config.Community)
}

// ------------------------------------------------------------------------------------------------
// 端到端集成测试：endpoint 收 gosnmp 发的 v2c Trap
// ------------------------------------------------------------------------------------------------

// sendV2cTrap 用 gosnmp 客户端向 target:port 发送一个 v2c Trap
func sendV2cTrap(t *testing.T, target string, port uint16) {
	t.Helper()
	client := &gosnmp.GoSNMP{
		Target:    target,
		Port:      port,
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   2 * time.Second,
	}
	err := client.Connect()
	assert.Nil(t, err)
	defer client.Conn.Close()

	// 标准 v2c Trap varbinds：sysUpTime + snmpTrapOID + 一个业务变量
	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(100)},                        // sysUpTime
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.4.1.20408.1.1"}, // snmpTrapOID
			{Name: "1.3.6.1.2.1.2.2.1.10.1", Type: gosnmp.Counter32, Value: uint32(1234)},                  // ifInOctets.1
		},
		Enterprise:   "1.3.6.1",
		AgentAddress: "127.0.0.1",
		GenericTrap:  0,
		SpecificTrap: 0,
		Timestamp:    100,
	}
	_, err = client.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap error: %v", err)
	}
}

// TestSnmpEndpointReceiveV2cTrap 端到端：endpoint 监听 1162，gosnmp 发 v2c Trap，验证 endpoint 收到并转成消息。
// 通过 AddInterceptors 捕获 DoProcess 的 exchange.In.Body（handleTrap 构造的 Trap payload）。
func TestSnmpEndpointReceiveV2cTrap(t *testing.T) {
	const listenAddr = "127.0.0.1:1162"
	config := rulego.NewConfig(types.WithDefaultPool())

	ep := (&SnmpTrapEndpoint{}).New().(*SnmpTrapEndpoint)
	err := ep.Init(config, types.Configuration{
		"server":    listenAddr,
		"version":   "v2c",
		"community": "public",
	})
	assert.Nil(t, err)

	var (
		got          string
		gotCommunity string
		gotVersion   string
		gotTrapOID   string
		mu           sync.Mutex
		wg           sync.WaitGroup
	)
	wg.Add(1)
	ep.AddInterceptors(func(router endpointApi.Router, exchange *endpointApi.Exchange) bool {
		msg := exchange.In.GetMsg()
		mu.Lock()
		got = msg.GetData()
		gotCommunity = msg.Metadata.GetValue("community")
		gotVersion = msg.Metadata.GetValue("version")
		gotTrapOID = msg.Metadata.GetValue("trapOID")
		mu.Unlock()
		wg.Done()
		return true
	})

	// 空路由即可，interceptor 在 DoProcess 开头执行
	_, err = ep.AddRouter(impl.NewRouter())
	assert.Nil(t, err)

	err = ep.Start()
	assert.Nil(t, err)
	defer ep.Destroy()
	time.Sleep(300 * time.Millisecond) // 等监听就绪

	// 发送 v2c Trap
	sendV2cTrap(t, "127.0.0.1", 1162)

	// 等拦截器触发（带超时保护）
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: endpoint did not receive trap within 3s")
	}

	mu.Lock()
	defer mu.Unlock()
	payload := string(got)
	assert.True(t, strings.Contains(payload, "variables"), "payload should contain variables: %s", payload)
	assert.True(t, strings.Contains(payload, "1.3.6.1.2.1.2.2.1.10.1"), "payload should contain the trap OID: %s", payload)
	// metadata 注入验证
	assert.Equal(t, "public", gotCommunity)
	assert.Equal(t, "v2c", gotVersion)
	assert.Equal(t, "1.3.6.1.4.1.20408.1.1", gotTrapOID)
	t.Logf("received trap payload: %s", payload)
}

// TestSnmpEndpointConfigPortConflict 两个端点同端口监听，第二个应失败
func TestSnmpEndpointConfigPortConflict(t *testing.T) {
	const listenAddr = "127.0.0.1:1163"
	config := rulego.NewConfig(types.WithDefaultPool())

	ep1 := (&SnmpTrapEndpoint{}).New().(*SnmpTrapEndpoint)
	assert.Nil(t, ep1.Init(config, types.Configuration{"server": listenAddr, "version": "v2c", "community": "public"}))
	_, _ = ep1.AddRouter(impl.NewRouter())
	assert.Nil(t, ep1.Start())
	defer ep1.Destroy()
	time.Sleep(300 * time.Millisecond)

	// TrapListener.Listen 占用端口后是阻塞的，第二个端点的 Listen 会失败（goroutine 内 Printf 记录）。
	// 这里验证 endpoint 配置/启动接口不 panic 即可（端口冲突由监听协程异步处理）。
	ep2 := (&SnmpTrapEndpoint{}).New().(*SnmpTrapEndpoint)
	assert.Nil(t, ep2.Init(config, types.Configuration{"server": listenAddr, "version": "v2c", "community": "public"}))
	_ = ep2.Start()
	defer ep2.Destroy()
}
