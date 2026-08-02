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

// modbusStub is minimal modbus TCP server: only accepts connections and counts, does not respond to modbus protocol.
// Used to verify "same-chain connection reuse" — simonvetter/modbus's Open() only does net.Dial for TCP,
// sends no modbus requests, so stub needs no protocol implementation for connection to succeed. accept count==1 is reuse proof.
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
			io.Copy(io.Discard, c) // Keep-alive connection, discard any requests
		}(c)
	}
}

// waitAccept polls waiting for accept count to reach want (race between Dial and stub goroutine counts, wait for stability).
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
		t.Fatalf("accept count: got %d want %d", got, want)
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

// TestModbusChainConnectionReuse verifies same-chain modbus connection reuse:
// Source (local mode) + borrower (ref://src) share same TCP connection (stub1 accept==1);
// Nodes connecting to different devices establish independent connections (stub2 accept==1).
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

	// Trigger connection establishment
	srcClient, err := src.SharedNode.GetSafely()
	if err != nil {
		t.Fatalf("src GetSafely: %v", err)
	}
	borrowerClient, err := borrower.SharedNode.GetSafely()
	if err != nil {
		t.Fatalf("borrower GetSafely: %v", err)
	}

	// Borrower reuses source's same client instance
	if borrowerClient != srcClient {
		t.Fatalf("borrower did not reuse src's client: src=%p borrower=%p", srcClient, borrowerClient)
	}
	// Reuse proof: source+borrower only occupy 1 TCP connection
	stub1.waitAccept(t, 1)

	// Nodes connecting to different devices establish independent connections
	otherClient, err := other.SharedNode.GetSafely()
	if err != nil {
		t.Fatalf("other GetSafely: %v", err)
	}
	if otherClient == srcClient {
		t.Fatal("other should establish independent connection, but reused src's client")
	}
	stub2.waitAccept(t, 1)
	stub1.waitAccept(t, 1) // stub1 still only has 1 (other goes to stub2)

	t.Logf("PASS: src+borrower share 1 TCP(stub1=%d), other independent(stub2=%d)", stub1.accepted(), stub2.accepted())
}

// TestModbusChainConnectionCloseUnregister verifies source unregisters from chain directory after Destroy, borrower no longer hits.
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
	if _, err := src.SharedNode.GetSafely(); err != nil { // Establish connection + register
		t.Fatalf("src GetSafely: %v", err)
	}
	if _, found := ruleEng.RootRuleChainCtx().Resources().Lookup("src"); !found {
		t.Fatal("src should have been registered to chain directory")
	}
	// Destroy source: should unregister
	src.Destroy()
	if _, found := ruleEng.RootRuleChainCtx().Resources().Lookup("src"); found {
		t.Fatal("src should have been unregistered from chain directory after Destroy")
	}
	t.Log("PASS: src unregistered from chain directory after Destroy")
}

// TestModbusDestroyCleansOpLock verifies owner Destroy cleans up operation lock entries for its underlying client (no leak).
// Covers Destroy path outside reconnect path — when nodes destroyed without reconnect (most common scenario), locks don't remain.
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
	// Simulate lock entry created by operation (executeWithRetry would register like this before operation)
	_ = modbusOpLocks.Lock(srcClient)
	if !modbusOpLocks.Has(srcClient) {
		t.Fatal("Lock entry should exist")
	}
	// owner Destroy should clean up lock entries (borrower doesn't clean, here src is owner)
	src.Destroy()
	if modbusOpLocks.Has(srcClient) {
		t.Fatal("Operation lock entry should be cleaned after owner Destroy (leak detected)")
	}
	t.Log("PASS: Operation lock entry cleaned after owner Destroy")
}
