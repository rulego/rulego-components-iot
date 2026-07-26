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
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// TestSnmpNodes 节点类型与默认配置
func TestSnmpNodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/snmpRead", r.Type())
	assert.NotNil(t, r.New())

	w := &WriteNode{}
	assert.Equal(t, "x/snmpWrite", w.Type())
	assert.NotNil(t, w.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1", rn.Config.Server)
	assert.Equal(t, 161, rn.Config.Port)
	assert.Equal(t, "v2c", rn.Config.Version)
	assert.Equal(t, "public", rn.Config.Community)
}

// TestToSnmpClientPoint 统一 Point(Addr=OID) 映射为 snmpclient.Point。
func TestToSnmpClientPoint(t *testing.T) {
	// get 默认
	p := iot_points.Point{Name: "sysName", Addr: "1.3.6.1.2.1.1.5.0"}
	cp := toSnmpClientPoint(p)
	assert.Equal(t, "sysName", cp.Name)
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", cp.OID)
	assert.Equal(t, "get", cp.Op)

	// walk 前缀
	p2 := iot_points.Point{Name: "ifTable", Addr: "walk:1.3.6.1.2.1.2.2"}
	cp2 := toSnmpClientPoint(p2)
	assert.Equal(t, "walk", cp2.Op)
	assert.Equal(t, "1.3.6.1.2.1.2.2", cp2.OID)
}

// TestConfigPropImpl ConfigProp 接口实现
func TestConfigPropImpl(t *testing.T) {
	c := Configuration{
		Server: "192.168.1.1", Port: 161, Version: "v3", Community: "private",
		Timeout: 3, SecurityLevel: "authPriv", UserName: "user",
		AuthProtocol: "SHA", AuthPassword: "ap", PrivProtocol: "AES", PrivPassword: "pp",
	}
	assert.Equal(t, "192.168.1.1", c.GetServer())
	assert.Equal(t, 161, c.GetPort())
	assert.Equal(t, "v3", c.GetVersion())
	assert.Equal(t, "private", c.GetCommunity())
	assert.Equal(t, 3, c.GetTimeout())
	assert.Equal(t, "authPriv", c.GetSecurityLevel())
	assert.Equal(t, "user", c.GetUserName())
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
