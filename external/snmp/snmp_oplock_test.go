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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// TestSnmpOpLockSerializes verifies concurrent ops on same client pointer are serialized (concurrency never exceeds 1).
// This is the cornerstone of same-chain ref:// shared connection safety: gosnmp single session is not concurrency-safe
// (gosnmp#489 concurrent response out-of-order), must serialize send/receive. Use with `go test -race` to further
// catch data races on unlocked paths.
func TestSnmpOpLockSerializes(t *testing.T) {
	ptr := &gosnmp.GoSNMP{}
	var cur int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu := snmpOpLocks.Lock(ptr)
			mu.Lock()
			if atomic.AddInt32(&cur, 1) > 1 {
				t.Errorf("shared client concurrency > 1 (lock not effective)")
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&cur, -1)
			mu.Unlock()
		}()
	}
	wg.Wait()
}

// TestSnmpOpLockDelete verifies Delete cleans up old connection lock entries after reconnect (no cumulative leak),
// and different client pointers map to independent locks (different connections can run in parallel).
func TestSnmpOpLockDelete(t *testing.T) {
	ptr := &gosnmp.GoSNMP{}
	mu1 := snmpOpLocks.Lock(ptr)
	snmpOpLocks.Delete(ptr)
	mu2 := snmpOpLocks.Lock(ptr)
	if mu1 == mu2 {
		t.Fatal("Delete should create new lock, returned same mutex (cleanup not effective)")
	}
	if snmpOpLocks.Lock(&gosnmp.GoSNMP{}) == mu2 {
		t.Fatal("different client pointers should map to different mutex")
	}
}
