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
	"testing"

	"github.com/rulego/rulego/test/assert"
)

// TestEncodeValue type strings -> Go values (for Write)
func TestEncodeValue(t *testing.T) {
	cases := []struct {
		name string
		val  string
		typ  string
		want interface{}
	}{
		{"BOOL true", "true", "BOOL", true},
		{"BOOL 1", "1", "BOOL", true},
		{"BOOL 0", "0", "BOOL", false},
		{"BYTE", "255", "BYTE", byte(255)},
		{"INT", "42", "INT", int16(42)},
		{"INT neg", "-1", "INT", int16(-1)},
		{"UINT", "256", "UINT", uint16(256)},
		{"DINT", "100000", "DINT", int32(100000)},
		{"UDINT", "4000000000", "UDINT", uint32(4000000000)},
		{"REAL", "23.5", "REAL", float32(23.5)},
		{"LREAL", "3.14", "LREAL", float64(3.14)},
		{"STRING", "Hello", "STRING", "Hello"},
	}
	for _, c := range cases {
		got, err := encodeValue(c.val, c.typ)
		assert.Nil(t, err)
		assert.Equal(t, c.want, got)
	}
}

// TestEncodeValueAlias type aliases (WORD=DINT same family)
func TestEncodeValueAlias(t *testing.T) {
	// WORD same as UINT16
	v, _ := encodeValue("10", "WORD")
	assert.Equal(t, uint16(10), v)
	// DWORD same as UINT32
	v, _ = encodeValue("10", "DWORD")
	assert.Equal(t, uint32(10), v)
	// FLOAT same as REAL
	v, _ = encodeValue("1.5", "FLOAT")
	assert.Equal(t, float32(1.5), v)
	// DOUBLE same as LREAL
	v, _ = encodeValue("1.5", "DOUBLE")
	assert.Equal(t, float64(1.5), v)
	// Unified FLOAT32 alias maps to REAL (float32)
	v, _ = encodeValue("1.5", "FLOAT32")
	assert.Equal(t, float32(1.5), v)
	// Unified FLOAT64 alias maps to LREAL (float64)
	v, _ = encodeValue("1.5", "FLOAT64")
	assert.Equal(t, float64(1.5), v)
	// SINT is signed int8 (CIP SINT = 8-bit signed), not byte
	v, _ = encodeValue("-1", "SINT")
	assert.Equal(t, int8(-1), v)
	// BYTE/USINT stay unsigned
	v, _ = encodeValue("255", "BYTE")
	assert.Equal(t, byte(255), v)
	v, _ = encodeValue("255", "USINT")
	assert.Equal(t, byte(255), v)
}

// TestEncodeValueErrors invalid input
func TestEncodeValueErrors(t *testing.T) {
	// Invalid number
	if _, err := encodeValue("abc", "INT"); err == nil {
		t.Fatal("encode INT abc should fail")
	}
	// Unsupported type
	if _, err := encodeValue("1", "UNKNOWN"); err == nil {
		t.Fatal("encode UNKNOWN should fail")
	}
}

// TestParseBoolValue bool value parsing
func TestParseBoolValue(t *testing.T) {
	for _, c := range []string{"true", "1", "TRUE"} {
		if v, _ := parseBoolValue(c); v != true {
			t.Fatalf("parseBoolValue(%q) want true", c)
		}
	}
	for _, c := range []string{"false", "0"} {
		if v, _ := parseBoolValue(c); v != false {
			t.Fatalf("parseBoolValue(%q) want false", c)
		}
	}
	if _, err := parseBoolValue("xyz"); err == nil {
		t.Fatal("parseBoolValue should fail for xyz")
	}
}
