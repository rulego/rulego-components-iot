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

// TestParseVersion SNMP version string -> constant
func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want gosnmp.SnmpVersion
	}{
		{"", gosnmp.Version2c}, // default v2c
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
	// Invalid version
	if _, err := parseVersion("v4"); err == nil {
		t.Fatal("parseVersion should fail for v4")
	}
}

// TestParseSecurityLevel v3 security level
func TestParseSecurityLevel(t *testing.T) {
	assert.Equal(t, gosnmp.NoAuthNoPriv, mustSecLevel("")) // default
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

// TestParseAuthProtocol v3 authentication protocol
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
	// Unknown protocol defaults to NoAuth
	assert.Equal(t, gosnmp.NoAuth, parseAuthProtocol("unknown"))
}

// TestParsePrivProtocol v3 encryption protocol
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
	// Unknown type with numeric value
	assert.Equal(t, "Asn1BER(0)", pduTypeString(gosnmp.EndOfContents))
}

// TestEncodeValue type strings -> Go values + Asn1BER (for Set).
// Counter32/Gauge32/TimeTicks must produce uint32 and Counter64 uint64, because gosnmp's
// marshalVarbind rejects Go int/int64 for those ASN.1 types.
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

	// Counter32 -> uint32 (gosnmp marshal requires uint32/uint for Counter32)
	v, typ, err = encodeValue("100", "counter32")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Counter32, typ)
	assert.Equal(t, uint32(100), v)

	// Gauge32 -> uint32
	v, typ, err = encodeValue("200", "gauge32")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Gauge32, typ)
	assert.Equal(t, uint32(200), v)

	// TimeTicks -> uint32
	v, typ, err = encodeValue("300", "timeticks")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.TimeTicks, typ)
	assert.Equal(t, uint32(300), v)

	// Counter64 -> uint64 (gosnmp marshalUint64 requires uint64)
	v, typ, err = encodeValue("5000000000", "counter64")
	assert.Nil(t, err)
	assert.Equal(t, gosnmp.Counter64, typ)
	assert.Equal(t, uint64(5000000000), v)

	// Unsupported type
	_, _, err = encodeValue("x", "unknown")
	if err == nil {
		t.Fatal("encodeValue should fail for unknown type")
	}
}

// TestPduToData PDU -> unified Data
func TestPduToData(t *testing.T) {
	// OctetString arrives from gosnmp as []byte; output must be string (not base64 in JSON).
	pdu := gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.1.5.0", Value: []byte("router1"), Type: gosnmp.OctetString}
	d := pduToData("sysName", pdu)
	assert.Equal(t, "sysName", d.Name)
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", d.Address)
	assert.Equal(t, "router1", d.Value)
	assert.Equal(t, "OctetString", d.Type)
	assert.Equal(t, "good", d.Quality)

	// Integer passes through unchanged
	pdu = gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.2.2.1.10.1", Value: 12345, Type: gosnmp.Counter32}
	d = pduToData("ifIn", pdu)
	assert.Equal(t, 12345, d.Value)
	assert.Equal(t, "good", d.Quality)

	// NoSuchObject -> quality=bad, empty value (not good-with-null)
	pdu = gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.1.5.0", Value: nil, Type: gosnmp.NoSuchObject}
	d = pduToData("missing", pdu)
	assert.Equal(t, "bad", d.Quality)
	assert.Nil(t, d.Value)
	assert.Equal(t, "NoSuchObject", d.Type)

	// NoSuchInstance -> quality=bad
	pdu = gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.1.5.0", Value: nil, Type: gosnmp.NoSuchInstance}
	d = pduToData("missing", pdu)
	assert.Equal(t, "bad", d.Quality)
	assert.Equal(t, "NoSuchInstance", d.Type)

	// nil value on a normal type -> quality=bad
	pdu = gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.1.5.0", Value: nil, Type: gosnmp.Integer}
	d = pduToData("nulval", pdu)
	assert.Equal(t, "bad", d.Quality)
}
