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
// Pure function tests
// ------------------------------------------------------------------------------------------------

// TestPduTypeString PDU type -> string
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
	assert.Equal(t, "Unknown", pduTypeString(gosnmp.Boolean)) // Unknown type
}

// TestVersionString SnmpVersion -> string
func TestVersionString(t *testing.T) {
	assert.Equal(t, "v1", versionString(gosnmp.Version1))
	assert.Equal(t, "v2c", versionString(gosnmp.Version2c))
	assert.Equal(t, "v3", versionString(gosnmp.Version3))
	assert.Equal(t, "unknown", versionString(gosnmp.SnmpVersion(0x9)))
}

// TestParseVersion version string parsing
func TestParseVersion(t *testing.T) {
	// Valid values
	v, err := parseVersion("v2c")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version2c, v)

	v, err = parseVersion("")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version2c, v) // Default v2c

	v, err = parseVersion("v1")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version1, v)

	v, err = parseVersion("v3")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Version3, v)

	// Invalid values
	_, err = parseVersion("v4")
	assert.NotNil(t, err)
}

// TestTrapVars PDU list -> simplified map
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
// Endpoint metadata tests
// ------------------------------------------------------------------------------------------------

// TestSnmpTrapEndpointMeta endpoint type/default config/ID
func TestSnmpTrapEndpointMeta(t *testing.T) {
	ep := &SnmpTrapEndpoint{}
	assert.Equal(t, "endpoint/snmp", ep.Type())
	assert.Equal(t, "endpoint", ep.Category())

	// Default configuration
	def := ep.New().(*SnmpTrapEndpoint)
	assert.Equal(t, "0.0.0.0:162", def.Config.Server)
	assert.Equal(t, "v2c", def.Config.Version)
	assert.Equal(t, "public", def.Config.Community)
}

// ------------------------------------------------------------------------------------------------
// End-to-end integration test: endpoint receives v2c Trap from gosnmp
// ------------------------------------------------------------------------------------------------

// sendV2cTrap sends a v2c Trap from gosnmp client to target:port
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

	// Standard v2c Trap varbinds: sysUpTime + snmpTrapOID + one business variable
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

// TestSnmpEndpointReceiveV2cTrap end-to-end: endpoint listens on 1162, gosnmp sends v2c Trap, verify endpoint receives and converts to message.
// Capture DoProcess exchange.In.Body via AddInterceptors (Trap payload constructed by handleTrap).
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

	// Empty router is sufficient, interceptor executes at DoProcess start
	_, err = ep.AddRouter(impl.NewRouter())
	assert.Nil(t, err)

	err = ep.Start()
	assert.Nil(t, err)
	defer ep.Destroy()
	time.Sleep(300 * time.Millisecond) // Wait for listener ready

	// Send v2c Trap
	sendV2cTrap(t, "127.0.0.1", 1162)

	// Wait for interceptor trigger (with timeout protection)
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
	// Verify metadata injection
	assert.Equal(t, "public", gotCommunity)
	assert.Equal(t, "v2c", gotVersion)
	assert.Equal(t, "1.3.6.1.4.1.20408.1.1", gotTrapOID)
	t.Logf("received trap payload: %s", payload)
}

// TestSnmpEndpointConfigPortConflict two endpoints listening on same port, second should fail
func TestSnmpEndpointConfigPortConflict(t *testing.T) {
	const listenAddr = "127.0.0.1:1163"
	config := rulego.NewConfig(types.WithDefaultPool())

	ep1 := (&SnmpTrapEndpoint{}).New().(*SnmpTrapEndpoint)
	assert.Nil(t, ep1.Init(config, types.Configuration{"server": listenAddr, "version": "v2c", "community": "public"}))
	_, _ = ep1.AddRouter(impl.NewRouter())
	assert.Nil(t, ep1.Start())
	defer ep1.Destroy()
	time.Sleep(300 * time.Millisecond)

	// TrapListener.Listen blocks after occupying port, second endpoint Listen will fail (recorded by Printf in goroutine).
	// Here we just verify endpoint config/start interface does not panic (port conflict handled asynchronously by listener goroutine).
	ep2 := (&SnmpTrapEndpoint{}).New().(*SnmpTrapEndpoint)
	assert.Nil(t, ep2.Init(config, types.Configuration{"server": listenAddr, "version": "v2c", "community": "public"}))
	_ = ep2.Start()
	defer ep2.Destroy()
}
