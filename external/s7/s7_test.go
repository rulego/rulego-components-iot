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

package s7

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robinson/gos7"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// TestS7Nodes node types and default configuration
func TestS7Nodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/s7Read", r.Type())
	assert.NotNil(t, r.New())

	w := &WriteNode{}
	assert.Equal(t, "x/s7Write", w.Type())
	assert.NotNil(t, w.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:102", rn.Config.Server)
	assert.Equal(t, 1, rn.Config.Slot)
}

// TestParseAddr parses unified Point.Addr to S7 addressing (Siemens official syntax).
func TestParseAddr(t *testing.T) {
	// DB double word
	area, db, addr, bit, isBit, err := parseAddr("DB1.DBD0")
	assert.Nil(t, err)
	assert.Equal(t, "DB", area)
	assert.Equal(t, 1, db)
	assert.Equal(t, 0, addr)
	assert.False(t, isBit)

	// DB bit
	_, _, _, bit, isBit, err = parseAddr("DB1.DBX0.1")
	assert.Nil(t, err)
	assert.Equal(t, 1, bit)
	assert.True(t, isBit)

	// M word
	area, _, addr, _, isBit, err = parseAddr("MW10")
	assert.Nil(t, err)
	assert.Equal(t, "M", area)
	assert.Equal(t, 10, addr)
	assert.False(t, isBit)

	// M bit shorthand
	_, _, _, bit, isBit, _ = parseAddr("M0.5")
	assert.Equal(t, 5, bit)
	assert.True(t, isBit)

	// I/Q
	area, _, _, _, _, _ = parseAddr("IW0")
	assert.Equal(t, "I", area)
	area, _, _, _, _, _ = parseAddr("Q0.3")
	assert.Equal(t, "Q", area)

	// % prefix
	area, _, _, _, _, _ = parseAddr("%M0.1")
	assert.Equal(t, "M", area)

	// invalid
	_, _, _, _, _, err = parseAddr("")
	assert.NotNil(t, err)
	_, _, _, _, _, err = parseAddr("X0")
	assert.NotNil(t, err)
	_, _, _, _, _, err = parseAddr("DB1") // missing DBT
	assert.NotNil(t, err)
}

// TestMapType unified type -> S7 native type.
func TestMapType(t *testing.T) {
	assert.Equal(t, "INT", mapType("INT16"))
	assert.Equal(t, "WORD", mapType("UINT16"))
	assert.Equal(t, "REAL", mapType("FLOAT32"))
	assert.Equal(t, "LREAL", mapType("FLOAT64"))
	assert.Equal(t, "BOOL", mapType("BOOL"))
	assert.Equal(t, "CUSTOM", mapType("CUSTOM")) // unknown pass-through
}

// TestS7ReadFailureNoPLC connection fails when no PLC, node routes to Failure.
func TestS7ReadFailureNoPLC(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/s7Read", types.Configuration{
		"server":  "127.0.0.1:19999",
		"rack":    0,
		"slot":    1,
		"timeout": 2,
		"points": []map[string]interface{}{
			{"name": "temperature", "addr": "DB1.DBD0", "type": "FLOAT32"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		if err == nil {
			t.Fatal("should have connection error for unreachable PLC")
		}
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for s7 read callback")
	}
}

// TestS7WriteFailureNoPLC s7Write also routes to Failure when no PLC
func TestS7WriteFailureNoPLC(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/s7Write", types.Configuration{
		"server":  "127.0.0.1:19999",
		"rack":    0,
		"slot":    1,
		"timeout": 2,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	writePayload := `[{"name":"t","addr":"DB1.DBD0","type":"FLOAT32","value":"1.0"}]`
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     writePayload,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for s7 write callback")
	}
}

// TestS7OpLockSerializes verifies concurrent ops on same handler pointer are serialized (concurrency never exceeds 1).
// This is the cornerstone of same-chain ref:// shared connection safety: gos7 single connection is not concurrency-safe,
// must serialize send/receive. Use with `go test -race` to further catch data races on unlocked paths.
func TestS7OpLockSerializes(t *testing.T) {
	ptr := &gos7.TCPClientHandler{}
	var cur int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu := s7OpLocks.Lock(ptr)
			mu.Lock()
			// concurrency within critical section must be <=1; widened sleep without lock will guarantee overlap
			if atomic.AddInt32(&cur, 1) > 1 {
				t.Errorf("shared handler concurrency > 1 (lock not effective)")
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&cur, -1)
			mu.Unlock()
		}()
	}
	wg.Wait()
}

// TestS7OpLockDelete verifies Delete cleans up old connection lock entries after reconnect (no cumulative leak),
// and different handler pointers map to independent locks (different connections can run in parallel).
func TestS7OpLockDelete(t *testing.T) {
	ptr := &gos7.TCPClientHandler{}
	mu1 := s7OpLocks.Lock(ptr)
	s7OpLocks.Delete(ptr)
	mu2 := s7OpLocks.Lock(ptr)
	if mu1 == mu2 {
		t.Fatal("Delete should create a new mutex but returned the same one (cleanup ineffective)")
	}
	// different handler pointers don't interfere
	if s7OpLocks.Lock(&gos7.TCPClientHandler{}) == mu2 {
		t.Fatal("different handler pointers should map to different mutex")
	}
}
