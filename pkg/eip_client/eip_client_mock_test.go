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
	"sync"
	"testing"
	"time"

	"github.com/danomagnum/gologix"
	"github.com/rulego/rulego/test/assert"
)

// startMockServer starts an in-process gologix server simulating ControlLogix.
// Returns tag provider (for pre-filling/validation) and cleanup function. Skips test if port 44818 is occupied.
var (
	mockServerOnce sync.Once
	mockProvider   *gologix.MapTagProvider
)

// startMockServer returns the shared mock server's tag provider. Started once (sync.Once) and
// never closed — closing the listener triggers gologix serveTCP's accept-error tight loop (library bug).
func startMockServer(t *testing.T) *gologix.MapTagProvider {
	mockServerOnce.Do(func() {
		if probe, err := net.Listen("tcp", "0.0.0.0:44818"); err != nil {
			t.Skipf("port 44818 unavailable (skip EIP mock test): %v", err)
		} else {
			probe.Close()
		}
		router := gologix.PathRouter{}
		mockProvider = &gologix.MapTagProvider{}
		path, err := gologix.ParsePath("1,0")
		if err != nil {
			t.Fatalf("parse path: %v", err)
		}
		router.Handle(path.Bytes(), mockProvider)
		srv := gologix.NewServer(&router)
		go func() { _ = srv.Serve() }()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if conn, err := net.DialTimeout("tcp", "127.0.0.1:44818", 100*time.Millisecond); err == nil {
				conn.Close()
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	return mockProvider
}

// TestReadPointsMockServer end-to-end: gologix server pre-fills various type tags -> ReadPoints reads -> verify value and type mapping
func TestReadPointsMockServer(t *testing.T) {
	provider := startMockServer(t)

	// Pre-fill: REAL / DINT / STRING (BOOL tested separately due to CIP BOOL bit addressing semantics)
	assert.Nil(t, provider.TagWrite("Temp", float32(23.5)))
	assert.Nil(t, provider.TagWrite("Count", int32(42)))
	assert.Nil(t, provider.TagWrite("Name", "Hello"))

	client := gologix.NewClient("127.0.0.1")
	if err := client.Connect(); err != nil {
		t.Fatalf("connect mock server: %v", err)
	}
	defer client.Disconnect()

	points := []Point{
		{Name: "Temperature", Tag: "Temp", Type: "REAL"},
		{Name: "Count", Tag: "Count", Type: "DINT"},
		{Name: "NameTag", Tag: "Name", Type: "STRING"},
	}
	data, err := ReadPoints(client, points, nil)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(data))

	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}

	// Verify each point quality=good and value correct
	if q := byName["Temperature"].Quality; q != "good" {
		t.Fatalf("Temp quality=%s (want good), err path may be broken", q)
	}
	assert.Equal(t, float32(23.5), byName["Temperature"].Value)
	assert.Equal(t, int32(42), byName["Count"].Value)
	assert.Equal(t, "Hello", byName["NameTag"].Value)
}

// TestWritePointsMockServer end-to-end: WritePoints writes -> provider data updated
func TestWritePointsMockServer(t *testing.T) {
	provider := startMockServer(t)

	assert.Nil(t, provider.TagWrite("Count", int32(0)))
	assert.Nil(t, provider.TagWrite("Temp", float32(0)))

	client := gologix.NewClient("127.0.0.1")
	if err := client.Connect(); err != nil {
		t.Fatalf("connect mock server: %v", err)
	}
	defer client.Disconnect()

	points := []Point{
		{Name: "Count", Tag: "Count", Type: "DINT", Value: "99"},
		{Name: "Temperature", Tag: "Temp", Type: "REAL", Value: "65.5"},
	}
	if err := WritePoints(client, points); err != nil {
		t.Fatalf("WritePoints: %v", err)
	}

	// Verify server-side data updated (TagWrite internally lowercases key)

	provider.Mutex.Lock()
	gotCount := provider.Data["count"]
	gotTemp := provider.Data["temp"]
	provider.Mutex.Unlock()

	assert.Equal(t, int32(99), gotCount)
	assert.Equal(t, float32(65.5), gotTemp)
}

// TestReadPointsBadTag missing point marked quality=bad, does not affect others
func TestReadPointsBadTag(t *testing.T) {
	provider := startMockServer(t)

	assert.Nil(t, provider.TagWrite("Good", int32(1)))

	client := gologix.NewClient("127.0.0.1")
	if err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect()

	points := []Point{
		{Name: "GoodPoint", Tag: "Good", Type: "DINT"},
		{Name: "BadPoint", Tag: "Missing", Type: "DINT"},
	}
	data, err := ReadPoints(client, points, nil)
	assert.Nil(t, err) // Single point failure does not return error
	assert.Equal(t, 2, len(data))

	byName := make(map[string]Data, len(data))
	for _, d := range data {
		byName[d.Name] = d
	}
	assert.Equal(t, "good", byName["GoodPoint"].Quality)
	assert.Equal(t, "bad", byName["BadPoint"].Quality)
}
