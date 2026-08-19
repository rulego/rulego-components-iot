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
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	snmpclient "github.com/rulego/rulego-components-iot/pkg/snmp_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// TestSnmpNodes node types and default configuration
func TestSnmpNodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/snmpRead", r.Type())
	assert.NotNil(t, r.New())

	w := &WriteNode{}
	assert.Equal(t, "x/snmpWrite", w.Type())
	assert.NotNil(t, w.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:161", rn.Config.Server)
	assert.Equal(t, "v2c", rn.Config.Version)
	assert.Equal(t, "public", rn.Config.Community)
}

// TestToSnmpClientPoint maps unified Point(Addr=OID) to snmpclient.Point.
func TestToSnmpClientPoint(t *testing.T) {
	// get by default
	p := iot_points.Point{Name: "sysName", Addr: "1.3.6.1.2.1.1.5.0"}
	cp := toSnmpClientPoint(p)
	assert.Equal(t, "sysName", cp.Name)
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", cp.OID)
	assert.Equal(t, "get", cp.Op)

	// walk prefix
	p2 := iot_points.Point{Name: "ifTable", Addr: "walk:1.3.6.1.2.1.2.2"}
	cp2 := toSnmpClientPoint(p2)
	assert.Equal(t, "walk", cp2.Op)
	assert.Equal(t, "1.3.6.1.2.1.2.2", cp2.OID)
}

// TestBuildReadDatas walk OID name suffix, scale/offset conversion (walk values
// included), non-numeric passthrough, bad point error.
func TestBuildReadDatas(t *testing.T) {
	now := time.Now()
	points := []iot_points.Point{
		{Name: "temp", Addr: "1.3.6.1.4.1.1.1", Scale: 0.1, Offset: -40},
		{Name: "sysName", Addr: "1.3.6.1.2.1.1.5.0", Scale: 10},
		{Name: "ifInOctets", Addr: "walk:1.3.6.1.2.1.2.2.1.10", Scale: 2},
	}
	cp := []snmpclient.Point{
		{Name: "temp", OID: "1.3.6.1.4.1.1.1", Op: "get"},
		{Name: "sysName", OID: "1.3.6.1.2.1.1.5.0", Op: "get"},
		{Name: "ifInOctets", OID: "1.3.6.1.2.1.2.2.1.10", Op: "walk"},
	}
	out := buildReadDatas([]snmpclient.Data{
		{Name: "temp", Address: "1.3.6.1.4.1.1.1", Value: 235, Quality: "good", Timestamp: now},
		{Name: "sysName", Address: "1.3.6.1.2.1.1.5.0", Value: "router-01", Quality: "good", Timestamp: now},
		{Name: "ifInOctets", Address: ".1.3.6.1.2.1.2.2.1.10.1", Value: 1000, Quality: "good", Timestamp: now},
		{Name: "ifInOctets", Address: ".1.3.6.1.2.1.2.2.1.10.2", Value: "n/a", Quality: "good", Timestamp: now},
		{Name: "temp", Address: "1.3.6.1.4.1.1.9", Value: nil, Quality: "bad", Timestamp: now},
	}, points, cp)

	assert.Equal(t, 5, len(out))
	assert.Equal(t, -16.5, out[0].Value) // 235*0.1-40
	assert.Equal(t, "router-01", out[1].Value)
	assert.Equal(t, "ifInOctets.1.3.6.1.2.1.2.2.1.10.1", out[2].Name)
	assert.Equal(t, 2000.0, out[2].Value) // 1000*2
	assert.Equal(t, "n/a", out[3].Value)
	assert.Equal(t, "read failed (quality=bad)", out[4].Error)
	assert.True(t, out[0].Timestamp > 0)
}

// TestConfigPropImpl ConfigProp interface implementation
func TestConfigPropImpl(t *testing.T) {
	c := Configuration{
		Server: "192.168.1.1:1161", Version: "v3", Community: "private",
		Timeout: 3, SecurityLevel: "authPriv", UserName: "user",
		AuthProtocol: "SHA", AuthPassword: "ap", PrivProtocol: "AES", PrivPassword: "pp",
	}
	assert.Equal(t, "192.168.1.1:1161", c.GetServer())
	assert.Equal(t, "v3", c.GetVersion())
	assert.Equal(t, "private", c.GetCommunity())
	assert.Equal(t, 3, c.GetTimeout())
	assert.Equal(t, "authPriv", c.GetSecurityLevel())
	assert.Equal(t, "user", c.GetUsername())
	assert.Equal(t, "SHA", c.GetAuthProtocol())
	assert.Equal(t, "ap", c.GetAuthPassword())
	assert.Equal(t, "AES", c.GetPrivProtocol())
	assert.Equal(t, "pp", c.GetPrivPassword())
}

// TestReadNodeOnMsgNoPoints verifies that read requests without points are routed to Failure.
func TestReadNodeOnMsgNoPoints(t *testing.T) {
	node := &ReadNode{
		Config: Configuration{
			Points: nil,
		},
	}
	err := node.SharedNode.InitWithClose(types.NewConfig(), node.Type(), "mock://snmp", false, func() (*gosnmp.GoSNMP, error) {
		return &gosnmp.GoSNMP{}, nil
	}, closeClient)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for snmp read callback")
	}
}

// TestWriteNodeOnMsgNoPoints verifies that write requests without points are routed to Failure.
func TestWriteNodeOnMsgNoPoints(t *testing.T) {
	node := &WriteNode{
		Config: Configuration{
			Points: nil,
		},
	}
	err := node.SharedNode.InitWithClose(types.NewConfig(), node.Type(), "mock://snmp", false, func() (*gosnmp.GoSNMP, error) {
		return &gosnmp.GoSNMP{}, nil
	}, closeClient)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for snmp write callback")
	}
}

// TestReadNodeOnMsgMissingClient verifies that missing SNMP clients are routed to Failure.
func TestReadNodeOnMsgMissingClient(t *testing.T) {
	node := &ReadNode{
		Config: Configuration{
			Points: []iot_points.Point{{Name: "sysName", Addr: "1.3.6.1.2.1.1.5.0"}},
		},
	}

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, base.ErrClientNotInit, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for snmp missing client callback")
	}
}
