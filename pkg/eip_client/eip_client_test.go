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

// TestEncodeValue 各类型字符串 -> Go 值（供 Write）
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

// TestEncodeValueAlias 类型别名（WORD=DINT 等同族）
func TestEncodeValueAlias(t *testing.T) {
	// WORD 同 UINT16
	v, _ := encodeValue("10", "WORD")
	assert.Equal(t, uint16(10), v)
	// DWORD 同 UINT32
	v, _ = encodeValue("10", "DWORD")
	assert.Equal(t, uint32(10), v)
	// FLOAT 同 REAL
	v, _ = encodeValue("1.5", "FLOAT")
	assert.Equal(t, float32(1.5), v)
	// DOUBLE 同 LREAL
	v, _ = encodeValue("1.5", "DOUBLE")
	assert.Equal(t, float64(1.5), v)
}

// TestEncodeValueErrors 非法输入
func TestEncodeValueErrors(t *testing.T) {
	// 非法数字
	if _, err := encodeValue("abc", "INT"); err == nil {
		t.Fatal("encode INT abc should fail")
	}
	// 不支持的类型
	if _, err := encodeValue("1", "UNKNOWN"); err == nil {
		t.Fatal("encode UNKNOWN should fail")
	}
}

// TestParseBoolValue 布尔值解析
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
