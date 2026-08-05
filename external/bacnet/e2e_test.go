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

package bacnet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	bacnetclient "github.com/rulego/rulego-components-iot/pkg/bacnet_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/engine"
	"github.com/rulego/rulego/test/assert"
)

// TestBacnetReadNodeE2E drives a full x/bacnetRead node through the rulego engine against an
// in-process MockServer (no hardware). Verifies the node wires points -> driver -> msg.Data correctly.
func TestBacnetReadNodeE2E(t *testing.T) {
	srv, err := bacnetclient.NewMockServer()
	assert.Nil(t, err)
	defer srv.Close()
	srv.SetRead(bacnetclient.ObjectTypeAnalogInput, 0, bacnetclient.PropertyPresentValue, bacnetclient.AppTagReal, 21.5)
	srv.SetRead(bacnetclient.ObjectTypeBinaryInput, 1, bacnetclient.PropertyPresentValue, bacnetclient.AppTagBoolean, true)

	var got string
	var mu sync.Mutex
	config := rulego.NewConfig(
		types.WithDefaultPool(),
		types.WithOnDebug(func(chainId, flowType, nodeId string, msg types.RuleMsg, relation string, err error) {
			if err != nil {
				t.Logf("[debug] %s/%s %s: %v", chainId, nodeId, relation, err)
				return
			}
			if nodeId == "read" && strings.HasPrefix(msg.GetData(), "[") {
				mu.Lock()
				got = msg.GetData()
				mu.Unlock()
			}
		}),
	)

	dsl := fmt.Sprintf(`{
		"ruleChain":{"id":"bacnet_e2e","root":true,"debugMode":true},
		"metadata":{"nodes":[
			{"id":"read","type":"x/bacnetRead","configuration":{"server":"%s","timeout":2,"points":[
				{"name":"temp","addr":"analog-input:0"},
				{"name":"fan","addr":"bi:1"}
			]}}
		],"connections":[]}
	}`, srv.Addr())

	rg, err := rulego.New("bacnet_e2e", []byte(dsl), engine.WithConfig(config))
	assert.Nil(t, err, "create rule engine")
	defer rg.Stop(context.Background())

	rg.OnMsg(types.NewMsg(0, "TRIGGER", types.JSON, types.NewMetadata(), ""))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := got != ""
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if got == "" {
		t.Fatal("no read output captured before timeout")
	}

	var data []iot_points.Data
	assert.Nil(t, json.Unmarshal([]byte(got), &data), "unmarshal output")
	if len(data) != 2 {
		t.Fatalf("got %d points, want 2", len(data))
	}
	if data[0].Name != "temp" || data[0].Value != 21.5 {
		t.Errorf("temp = %+v, want value 21.5", data[0])
	}
	if data[1].Name != "fan" || data[1].Value != true {
		t.Errorf("fan = %+v, want value true", data[1])
	}
}

// TestBacnetReadReal runs against a real BACnet/IP device. Requires E2E_BACNET_ADDR (host[:port])
// and E2E_BACNET_POINT (e.g. analog-input:0); otherwise skips.
func TestBacnetReadReal(t *testing.T) {
	addr := os.Getenv("E2E_BACNET_ADDR")
	point := os.Getenv("E2E_BACNET_POINT")
	if addr == "" || point == "" {
		t.Skip("set E2E_BACNET_ADDR and E2E_BACNET_POINT to enable real-device bacnet read")
	}
	c, err := bacnetclient.NewClient(addr, 5*time.Second)
	assert.Nil(t, err)
	defer c.Close()

	a, err := ParsePointAddr(point)
	assert.Nil(t, err)
	val, err := c.ReadProperty(a.ObjectType, a.Instance, a.Property)
	assert.Nil(t, err)
	t.Logf("read %s on %s = %v", point, addr, val)
}
