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

package eip

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/danomagnum/gologix"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// TestEipNodes node types and default configuration
func TestEipNodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/eipRead", r.Type())
	assert.NotNil(t, r.New())

	w := &WriteNode{}
	assert.Equal(t, "x/eipWrite", w.Type())
	assert.NotNil(t, w.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:44818", rn.Config.Server)
	assert.Equal(t, 0, rn.Config.Slot)
}

// TestToEipClientPoint maps unified Point(Addr=tag) to eipclient.Point.
func TestToEipClientPoint(t *testing.T) {
	p := iot_points.Point{Name: "temperature", Addr: "MyDB.Temp", Type: "FLOAT32"}
	cp := toEipClientPoint(p)
	assert.Equal(t, "temperature", cp.Name)
	assert.Equal(t, "MyDB.Temp", cp.Tag)
	assert.Equal(t, "REAL", cp.Type) // FLOAT32 -> REAL
}

// TestMapType unified type -> EIP native type.
func TestMapType(t *testing.T) {
	assert.Equal(t, "INT", mapType("INT16"))
	assert.Equal(t, "DINT", mapType("INT32"))
	assert.Equal(t, "REAL", mapType("FLOAT32"))
	assert.Equal(t, "BOOL", mapType("BOOL"))
	assert.Equal(t, "STRING", mapType("STRING"))
	assert.Equal(t, "CUSTOM", mapType("CUSTOM")) // unknown pass-through
}

// startTestServer starts in-process gologix server to simulate ControlLogix (skip if port 44818 occupied)
func startTestServer(t *testing.T) (*gologix.MapTagProvider, func()) {
	if probe, err := net.Listen("tcp", "0.0.0.0:44818"); err != nil {
		t.Skipf("port 44818 unavailable (skip EIP rule-chain test): %v", err)
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
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:44818", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return &provider, func() {
		if srv.TCPListener != nil {
			srv.TCPListener.Close()
		}
		if srv.UDPListener != nil {
			srv.UDPListener.Close()
		}
	}
}

// TestEipReadNode eipRead node end-to-end: connect to mock PLC -> read tags -> output Data list.
func TestEipReadNode(t *testing.T) {
	provider, cleanup := startTestServer(t)
	defer cleanup()
	provider.TagWrite("Temp", float32(23.5))
	provider.TagWrite("Count", int32(7))

	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/eipRead", types.Configuration{
		"server":  "127.0.0.1",
		"slot":    0,
		"timeout": 5,
		"points": []map[string]interface{}{
			{"name": "temperature", "addr": "Temp", "type": "FLOAT32"},
			{"name": "counter", "addr": "Count", "type": "INT32"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		assert.True(t, strings.Contains(msg.GetData(), "temperature"), "msg.Data should contain temperature")
		assert.True(t, strings.Contains(msg.GetData(), "23.5"), "msg.Data should contain REAL value 23.5")
		assert.True(t, strings.Contains(msg.GetData(), "counter"), "msg.Data should contain counter")
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for eip read callback")
	}
}

// TestEipWriteNode eipWrite node end-to-end: read points from msg.Data -> write to mock PLC -> verify server data updated.
func TestEipWriteNode(t *testing.T) {
	provider, cleanup := startTestServer(t)
	defer cleanup()
	provider.TagWrite("Count", int32(0))
	provider.TagWrite("Temp", float32(0))

	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/eipWrite", types.Configuration{
		"server":  "127.0.0.1",
		"slot":    0,
		"timeout": 5,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	writePayload := `[{"name":"counter","addr":"Count","type":"INT32","value":"128"},{"name":"temperature","addr":"Temp","type":"FLOAT32","value":"65.5"}]`
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     writePayload,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for eip write callback")
	}

	provider.Mutex.Lock()
	gotCount := provider.Data["count"]
	gotTemp := provider.Data["temp"]
	provider.Mutex.Unlock()
	assert.Equal(t, int32(128), gotCount)
	assert.Equal(t, float32(65.5), gotTemp)
}
