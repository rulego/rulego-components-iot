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

package eipclient

import (
	"net"
	"testing"
	"time"

	"github.com/danomagnum/gologix"
	"github.com/rulego/rulego/test/assert"
)

// startMockServer 启动一个进程内 gologix server 模拟 ControlLogix。
// 返回 tag 提供器（用于预填/校验）和清理函数。端口 44818 被占用则跳过测试。
func startMockServer(t *testing.T) (*gologix.MapTagProvider, func()) {
	if probe, err := net.Listen("tcp", "0.0.0.0:44818"); err != nil {
		t.Skipf("port 44818 unavailable (skip EIP mock test): %v", err)
	} else {
		probe.Close()
	}
	router := gologix.PathRouter{}
	provider := gologix.MapTagProvider{}
	path, err := gologix.ParsePath("1,0")
	if err != nil {
		t.Fatalf("parse path: %v", err)
	}
	router.Handle(path.Bytes(), &provider)
	srv := gologix.NewServer(&router)
	go func() { _ = srv.Serve() }()

	// 等待 listener 就绪
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:44818", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cleanup := func() {
		if srv.TCPListener != nil {
			srv.TCPListener.Close()
		}
		if srv.UDPListener != nil {
			srv.UDPListener.Close()
		}
	}
	return &provider, cleanup
}

// TestReadPointsMockServer 端到端：gologix server 预填各类型 tag -> ReadPoints 读取 -> 验证值与类型映射
func TestReadPointsMockServer(t *testing.T) {
	provider, cleanup := startMockServer(t)
	defer cleanup()

	// 预填：REAL / DINT / STRING（BOOL 单独测，因 CIP BOOL 位寻址语义特殊）
	assert.Nil(t, provider.TagWrite("Temp", float32(23.5)))
	assert.Nil(t, provider.TagWrite("Count", int32(42)))
	assert.Nil(t, provider.TagWrite("Name", "Hello"))

	client := gologix.NewClient("127.0.0.1")
	if err := client.Connect(); err != nil {
		t.Fatalf("connect mock server: %v", err)
	}
	defer client.Disconnect()

	points := []Point{
		{Name: "温度", Tag: "Temp", Type: "REAL"},
		{Name: "计数", Tag: "Count", Type: "DINT"},
		{Name: "名称", Tag: "Name", Type: "STRING"},
	}
	data, err := ReadPoints(client, points, nil)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(data))

	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}

	// 验证每个点位 quality=good 且值正确
	if q := byName["温度"].Quality; q != "good" {
		t.Fatalf("Temp quality=%s (want good), err path may be broken", q)
	}
	assert.Equal(t, float32(23.5), byName["温度"].Value)
	assert.Equal(t, int32(42), byName["计数"].Value)
	assert.Equal(t, "Hello", byName["名称"].Value)
}

// TestWritePointsMockServer 端到端：WritePoints 写入 -> provider 数据被更新
func TestWritePointsMockServer(t *testing.T) {
	provider, cleanup := startMockServer(t)
	defer cleanup()

	assert.Nil(t, provider.TagWrite("Count", int32(0)))
	assert.Nil(t, provider.TagWrite("Temp", float32(0)))

	client := gologix.NewClient("127.0.0.1")
	if err := client.Connect(); err != nil {
		t.Fatalf("connect mock server: %v", err)
	}
	defer client.Disconnect()

	points := []Point{
		{Name: "计数", Tag: "Count", Type: "DINT", Value: "99"},
		{Name: "温度", Tag: "Temp", Type: "REAL", Value: "65.5"},
	}
	if err := WritePoints(client, points); err != nil {
		t.Fatalf("WritePoints: %v", err)
	}

	// 验证 server 端数据被更新（TagWrite 内部转小写 key）
	provider.Mutex.Lock()
	gotCount := provider.Data["count"]
	gotTemp := provider.Data["temp"]
	provider.Mutex.Unlock()

	assert.Equal(t, int32(99), gotCount)
	assert.Equal(t, float32(65.5), gotTemp)
}

// TestReadPointsBadTag 点位不存在时标记 quality=bad，不影响其它点位
func TestReadPointsBadTag(t *testing.T) {
	provider, cleanup := startMockServer(t)
	defer cleanup()

	assert.Nil(t, provider.TagWrite("Good", int32(1)))

	client := gologix.NewClient("127.0.0.1")
	if err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect()

	points := []Point{
		{Name: "好点", Tag: "Good", Type: "DINT"},
		{Name: "坏点", Tag: "Missing", Type: "DINT"},
	}
	data, err := ReadPoints(client, points, nil)
	assert.Nil(t, err) // 单点失败不返回错误
	assert.Equal(t, 2, len(data))

	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, "good", byName["好点"].Quality)
	assert.Equal(t, "bad", byName["坏点"].Quality)
}
