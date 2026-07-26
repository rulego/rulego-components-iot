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

package snmpclient

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego/test/assert"
)

// TestParseVersion SNMP 版本字符串 -> 常量
func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want gosnmp.SnmpVersion
	}{
		{"", gosnmp.Version2c}, // 默认 v2c
		{"v2c", gosnmp.Version2c},
		{"v2", gosnmp.Version2c},
		{"2c", gosnmp.Version2c},
		{"v1", gosnmp.Version1},
		{"1", gosnmp.Version1},
		{"v3", gosnmp.Version3},
		{"3", gosnmp.Version3},
	}
	for _, c := range cases {
		got, err := parseVersion(c.in)
		assert.Nil(t, err)
		assert.Equal(t, c.want, got)
	}
	// 非法版本
	if _, err := parseVersion("v4"); err == nil {
		t.Fatal("parseVersion should fail for v4")
	}
}

// TestParseSecurityLevel v3 安全级别
func TestParseSecurityLevel(t *testing.T) {
	assert.Equal(t, gosnmp.NoAuthNoPriv, mustSecLevel("")) // 默认
	assert.Equal(t, gosnmp.NoAuthNoPriv, mustSecLevel("noAuthNoPriv"))
	assert.Equal(t, gosnmp.AuthNoPriv, mustSecLevel("authNoPriv"))
	assert.Equal(t, gosnmp.AuthPriv, mustSecLevel("authPriv"))
	if _, err := parseSecurityLevel("xxx"); err == nil {
		t.Fatal("parseSecurityLevel should fail for xxx")
	}
}

func mustSecLevel(s string) gosnmp.SnmpV3MsgFlags {
	v, err := parseSecurityLevel(s)
	if err != nil {
		panic(err)
	}
	return v
}

// TestParseAuthProtocol v3 认证协议
func TestParseAuthProtocol(t *testing.T) {
	cases := map[string]gosnmp.SnmpV3AuthProtocol{
		"":       gosnmp.NoAuth,
		"NONE":   gosnmp.NoAuth,
		"MD5":    gosnmp.MD5,
		"SHA":    gosnmp.SHA,
		"SHA256": gosnmp.SHA256,
		"SHA512": gosnmp.SHA512,
	}
	for in, want := range cases {
		assert.Equal(t, want, parseAuthProtocol(in))
	}
	// 未知协议默认 NoAuth
	assert.Equal(t, gosnmp.NoAuth, parseAuthProtocol("unknown"))
}

// TestParsePrivProtocol v3 加密协议
func TestParsePrivProtocol(t *testing.T) {
	cases := map[string]gosnmp.SnmpV3PrivProtocol{
		"":       gosnmp.NoPriv,
		"NONE":   gosnmp.NoPriv,
		"DES":    gosnmp.DES,
		"AES":    gosnmp.AES,
		"AES256": gosnmp.AES256,
	}
	for in, want := range cases {
		assert.Equal(t, want, parsePrivProtocol(in))
	}
	assert.Equal(t, gosnmp.NoPriv, parsePrivProtocol("unknown"))
}

// TestPduTypeString PDU 类型 -> 字符串
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
	// 未知类型带数值
	assert.Equal(t, "Asn1BER(0)", pduTypeString(gosnmp.EndOfContents))
}

// TestEncodeValue 各类型字符串 -> Go 值 + Asn1BER（供 Set）
func TestEncodeValue(t *testing.T) {
	// Integer
	v, typ, err := encodeValue("42", "integer")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Integer, typ)
	assert.Equal(t, 42, v)

	// String
	v, typ, err = encodeValue("hello", "string")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.OctetString, typ)
	assert.Equal(t, "hello", v)

	// OID
	v, typ, err = encodeValue("1.3.6.1", "oid")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.ObjectIdentifier, typ)
	assert.Equal(t, "1.3.6.1", v)

	// Counter32
	v, typ, err = encodeValue("100", "counter32")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Counter32, typ)
	assert.Equal(t, 100, v)

	// 不支持的类型
	_, _, err = encodeValue("x", "unknown")
	if err == nil {
		t.Fatal("encodeValue should fail for unknown type")
	}
}

// TestPduToData PDU -> 统一 Data
func TestPduToData(t *testing.T) {
	pdu := gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.1.5.0", Value: "router1", Type: gosnmp.OctetString}
	d := pduToData("sysName", pdu)
	assert.Equal(t, "sysName", d.Name)
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", d.Address)
	assert.Equal(t, "router1", d.Value)
	assert.Equal(t, "OctetString", d.Type)
	assert.Equal(t, "good", d.Quality)
}
