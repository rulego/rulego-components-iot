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
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/engine"
)

// modbusStub 是最小 modbus TCP server：仅 accept 连接并计数，不响应 modbus 协议。
// 用于验证「同链连接复用」——simonvetter/modbus 的 Open() 对 TCP 仅 net.Dial 建连，
// 不发 modbus 请求，故 stub 无需实现协议即可让连接建立成功。accept 计数==1 即复用铁证。
type modbusStub struct {
	ln     net.Listener
	accept int32
}

func newModbusStub(t *testing.T) *modbusStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return &modbusStub{ln: ln}
}

func (s *modbusStub) addr() string  { return s.ln.Addr().String() }
func (s *modbusStub) close()        { s.ln.Close() }
func (s *modbusStub) accepted() int { return int(atomic.LoadInt32(&s.accept)) }

func (s *modbusStub) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		atomic.AddInt32(&s.accept, 1)
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(io.Discard, c) // 保活连接，丢弃任何请求
		}(c)
	}
}

// waitAccept 轮询等待 accept 计数达到 want（Dial 与 stub goroutine 计数间有竞态，需等稳定）。
func (s *modbusStub) waitAccept(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.accepted() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := s.accepted(); got != want {
		t.Fatalf("accept 计数: got %d want %d", got, want)
	}
}

func getModbusNode(t *testing.T, eng *engine.RuleEngine, id string) *ModbusNode {
	t.Helper()
	nc, ok := eng.RootRuleChainCtx().GetNodeById(types.RuleNodeId{Id: id})
	if !ok {
		t.Fatalf("node %s not found", id)
	}
	rnc, ok := nc.(*engine.RuleNodeCtx)
	if !ok {
		t.Fatalf("node %s ctx type %T", id, nc)
	}
	node, ok := rnc.Node.(*ModbusNode)
	if !ok {
		t.Fatalf("node %s type %T not *ModbusNode", id, rnc.Node)
	}
	return node
}

// TestModbusChainConnectionReuse 验证同链 modbus 连接复用：
// 源（本地模式）+ 借用方（ref://src）共享同一条 TCP 连接（stub1 accept==1）；
// 连不同设备的节点独立建连（stub2 accept==1）。
func TestModbusChainConnectionReuse(t *testing.T) {
	stub1 := newModbusStub(t)
	defer stub1.close()
	go stub1.serve()
	stub2 := newModbusStub(t)
	defer stub2.close()
	go stub2.serve()

	chain := fmt.Sprintf(`{
  "ruleChain": {"id": "test_modbus_chain_reuse", "root": true},
  "metadata": {
    "firstNodeIndex": 0,
    "nodes": [
      {"id":"src","type":"x/modbus","configuration":{"server":"tcp://%s","cmd":"ReadRegisters","address":"0","quantity":"1"}},
      {"id":"borrower","type":"x/modbus","configuration":{"server":"ref://src","cmd":"ReadRegisters","address":"0","quantity":"1"}},
      {"id":"other","type":"x/modbus","configuration":{"server":"tcp://%s","cmd":"ReadRegisters","address":"0","quantity":"1"}}
    ]
  }
}`, stub1.addr(), stub2.addr())

	eng, err := rulego.New("test_modbus_chain_reuse", []byte(chain))
	if err != nil {
		t.Fatalf("load chain: %v", err)
	}
	defer rulego.Del("test_modbus_chain_reuse")
	ruleEng := eng.(*engine.RuleEngine)

	src := getModbusNode(t, ruleEng, "src")
	borrower := getModbusNode(t, ruleEng, "borrower")
	other := getModbusNode(t, ruleEng, "other")

	// 触发建连
	srcClient, err := src.SharedNode.GetSafely()
	if err != nil {
		t.Fatalf("src GetSafely: %v", err)
	}
	borrowerClient, err := borrower.SharedNode.GetSafely()
	if err != nil {
		t.Fatalf("borrower GetSafely: %v", err)
	}

	// 借用方复用源的同一 client 实例
	if borrowerClient != srcClient {
		t.Fatalf("borrower 未复用 src 的 client：src=%p borrower=%p", srcClient, borrowerClient)
	}
	// 复用铁证：源+借用方只占 1 条 TCP 连接
	stub1.waitAccept(t, 1)

	// 连不同设备的节点独立建连
	otherClient, err := other.SharedNode.GetSafely()
	if err != nil {
		t.Fatalf("other GetSafely: %v", err)
	}
	if otherClient == srcClient {
		t.Fatal("other 应独立建连，却复用了 src 的 client")
	}
	stub2.waitAccept(t, 1)
	stub1.waitAccept(t, 1) // stub1 仍只有 1 条（other 走 stub2）

	t.Logf("PASS: src+borrower 共享 1 条 TCP(stub1=%d)，other 独立(stub2=%d)", stub1.accepted(), stub2.accepted())
}

// TestModbusChainConnectionCloseUnregister 验证源 Destroy 后从同链目录注销，借用方不再命中。
func TestModbusChainConnectionCloseUnregister(t *testing.T) {
	stub := newModbusStub(t)
	defer stub.close()
	go stub.serve()

	chain := fmt.Sprintf(`{
  "ruleChain": {"id": "test_modbus_chain_close", "root": true},
  "metadata": {
    "firstNodeIndex": 0,
    "nodes": [
      {"id":"src","type":"x/modbus","configuration":{"server":"tcp://%s","cmd":"ReadRegisters","address":"0","quantity":"1"}},
      {"id":"borrower","type":"x/modbus","configuration":{"server":"ref://src","cmd":"ReadRegisters","address":"0","quantity":"1"}}
    ]
  }
}`, stub.addr())

	eng, err := rulego.New("test_modbus_chain_close", []byte(chain))
	if err != nil {
		t.Fatalf("load chain: %v", err)
	}
	defer rulego.Del("test_modbus_chain_close")
	ruleEng := eng.(*engine.RuleEngine)

	src := getModbusNode(t, ruleEng, "src")
	if _, err := src.SharedNode.GetSafely(); err != nil { // 建连 + 注册
		t.Fatalf("src GetSafely: %v", err)
	}
	if _, found := ruleEng.RootRuleChainCtx().Resources().Lookup("src"); !found {
		t.Fatal("src 应已注册到同链目录")
	}
	// 销毁源：应注销
	src.Destroy()
	if _, found := ruleEng.RootRuleChainCtx().Resources().Lookup("src"); found {
		t.Fatal("src Destroy 后应从同链目录注销")
	}
	t.Log("PASS: src Destroy 后已从同链目录注销")
}

// TestModbusDestroyCleansOpLock 验证 owner Destroy 后其底层 client 的操作锁条目被清理（无泄漏）。
// 覆盖 reconnect 路径之外的 Destroy 路径——节点在未重连情况下被销毁（最常见场景）时锁不残留。
func TestModbusDestroyCleansOpLock(t *testing.T) {
	stub := newModbusStub(t)
	defer stub.close()
	go stub.serve()

	chain := fmt.Sprintf(`{
  "ruleChain": {"id": "test_modbus_destroy_lock", "root": true},
  "metadata": {
    "firstNodeIndex": 0,
    "nodes": [
      {"id":"src","type":"x/modbus","configuration":{"server":"tcp://%s","cmd":"ReadRegisters","address":"0","quantity":"1"}}
    ]
  }
}`, stub.addr())

	eng, err := rulego.New("test_modbus_destroy_lock", []byte(chain))
	if err != nil {
		t.Fatalf("load chain: %v", err)
	}
	defer rulego.Del("test_modbus_destroy_lock")
	ruleEng := eng.(*engine.RuleEngine)

	src := getModbusNode(t, ruleEng, "src")
	srcClient, err := src.SharedNode.GetSafely()
	if err != nil {
		t.Fatalf("src GetSafely: %v", err)
	}
	// 模拟操作产生的锁条目（executeWithRetry 会在操作前这样注册）
	_ = modbusOpLocks.Lock(srcClient)
	if !modbusOpLocks.Has(srcClient) {
		t.Fatal("锁条目应已存在")
	}
	// owner Destroy 应清理锁条目（borrower 不清理，此处 src 为 owner）
	src.Destroy()
	if modbusOpLocks.Has(srcClient) {
		t.Fatal("owner Destroy 后操作锁条目应被清理（检测到泄漏）")
	}
	t.Log("PASS: owner Destroy 后操作锁条目已清理")
}
