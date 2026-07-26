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

package s7client

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/rulego/rulego/test/assert"
)

// TestSizeOfType 各类型字节数（协议语义，非代码派生）
func TestSizeOfType(t *testing.T) {
	cases := map[string]int{
		"BOOL": 1, "BYTE": 1,
		"INT": 2, "WORD": 2,
		"DINT": 4, "DWORD": 4, "REAL": 4,
		"LREAL":   8,
		"STRING":  256,
		"UNKNOWN": 0,
	}
	for typ, want := range cases {
		assert.Equal(t, want, sizeOfType(typ))
	}
}

// TestParseArea 区域字符串 -> 区域 ID
func TestParseArea(t *testing.T) {
	assert.Equal(t, 0x84, mustArea("DB"))
	assert.Equal(t, 0x83, mustArea("M"))
	assert.Equal(t, 0x81, mustArea("I"))
	assert.Equal(t, 0x82, mustArea("Q"))
	// 大小写不敏感
	assert.Equal(t, 0x84, mustArea("db"))
	// 未知区域报错
	if _, err := parseArea("X"); err == nil {
		t.Fatal("parseArea should fail for unknown area X")
	}
}

func mustArea(s string) int {
	v, err := parseArea(s)
	if err != nil {
		panic(err)
	}
	return v
}

// TestFormatAddr 可读地址串
func TestFormatAddr(t *testing.T) {
	cases := []struct {
		name string
		p    Point
		want string
	}{
		{"DB REAL", Point{Area: "DB", DbNumber: 1, Address: 8, Type: "REAL"}, "DB1.8"},
		{"DB BOOL", Point{Area: "DB", DbNumber: 1, Address: 8, Type: "BOOL", BitOffset: 3}, "DB1.8.3"},
		{"M BOOL", Point{Area: "M", Address: 10, Type: "BOOL", BitOffset: 0}, "M10.0"},
		{"I BYTE", Point{Area: "I", Address: 5, Type: "BYTE"}, "I5"},
		{"Q INT", Point{Area: "Q", Address: 20, Type: "INT"}, "Q20"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, formatAddr(c.p))
	}
}

// TestDecodeScalar 各类型解析（大端字节序，S7 默认）
func TestDecodeScalar(t *testing.T) {
	// BOOL 位偏移
	buf1 := []byte{0x04} // 0b00000100
	if v, _ := decodeScalar(buf1, "BOOL", 2); v != true {
		t.Fatalf("BOOL bit2 of 0x04 = want true, got %v", v)
	}
	if v, _ := decodeScalar(buf1, "BOOL", 1); v != false {
		t.Fatalf("BOOL bit1 of 0x04 = want false, got %v", v)
	}

	// BYTE
	if v, _ := decodeScalar([]byte{0x2A}, "BYTE", 0); v != byte(42) {
		t.Fatalf("BYTE 0x2A = want 42, got %v", v)
	}

	// INT 有符号 16 位大端
	assert.Equal(t, int16(42), decodeOrFail(t, []byte{0x00, 0x2A}, "INT"))
	assert.Equal(t, int16(-1), decodeOrFail(t, []byte{0xFF, 0xFF}, "INT"))

	// WORD 无符号 16 位大端：0x0100 = 256
	assert.Equal(t, uint16(256), decodeOrFail(t, []byte{0x01, 0x00}, "WORD"))

	// DINT 有符号 32 位大端
	assert.Equal(t, int32(42), decodeOrFail(t, []byte{0x00, 0x00, 0x00, 0x2A}, "DINT"))

	// DWORD 无符号 32 位
	assert.Equal(t, uint32(0x01020304), decodeOrFail(t, []byte{0x01, 0x02, 0x03, 0x04}, "DWORD"))

	// REAL 32 位浮点（IEEE754 大端）：23.5 = 0x41BC0000
	rebuf := make([]byte, 4)
	binary.BigEndian.PutUint32(rebuf, math.Float32bits(23.5))
	assert.Equal(t, float32(23.5), decodeOrFail(t, rebuf, "REAL"))

	// LREAL 64 位浮点
	lrbuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lrbuf, math.Float64bits(3.14159))
	if v := decodeOrFail(t, lrbuf, "LREAL"); v != float64(3.14159) {
		t.Fatalf("LREAL mismatch: got %v", v)
	}

	// STRING S7 格式：[maxLen][actualLen][chars...]
	sbuf := make([]byte, 8)
	sbuf[0] = 254
	sbuf[1] = 5
	copy(sbuf[2:], []byte("Hello"))
	assert.Equal(t, "Hello", decodeOrFail(t, sbuf, "STRING"))
}

func decodeOrFail(t *testing.T, buf []byte, typ string) interface{} {
	v, err := decodeScalar(buf, typ, 0)
	if err != nil {
		t.Fatalf("decodeScalar %s error: %v", typ, err)
	}
	return v
}

// TestDecodeArray 数组解析
func TestDecodeArray(t *testing.T) {
	// 2 个 INT 大端：[0,1, 0,2]
	v, err := decodeArray([]byte{0x00, 0x01, 0x00, 0x02}, "INT", 2)
	if err != nil {
		t.Fatal(err)
	}
	arr := v.([]interface{})
	assert.Equal(t, 2, len(arr))
	assert.Equal(t, int16(1), arr[0])
	assert.Equal(t, int16(2), arr[1])
}

// TestEncodeScalar 各类型编码（与 decode 往返一致）
func TestEncodeScalar(t *testing.T) {
	// INT
	b, err := encodeScalar("42", "INT", 0)
	if err != nil || len(b) != 2 || b[0] != 0 || b[1] != 42 {
		t.Fatalf("encode INT 42 = %v err %v", b, err)
	}
	// REAL 往返
	rb, _ := encodeScalar("23.5", "REAL", 0)
	if v, _ := decodeScalar(rb, "REAL", 0); v != float32(23.5) {
		t.Fatalf("REAL roundtrip failed: got %v", v)
	}
	// LREAL 往返
	lb, _ := encodeScalar("3.14", "LREAL", 0)
	if v, _ := decodeScalar(lb, "LREAL", 0); v != float64(3.14) {
		t.Fatalf("LREAL roundtrip failed: got %v", v)
	}
	// STRING：[254][len][chars]
	sb, _ := encodeScalar("Hi", "STRING", 0)
	if len(sb) != 256 || sb[0] != 254 || sb[1] != 2 || sb[2] != 'H' || sb[3] != 'i' {
		t.Fatalf("encode STRING Hi unexpected: %v...", sb[:6])
	}
	// BYTE
	bb, _ := encodeScalar("255", "BYTE", 0)
	if len(bb) != 1 || bb[0] != 255 {
		t.Fatalf("encode BYTE 255 = %v", bb)
	}
	// 不支持的类型
	if _, err := encodeScalar("1", "UNKNOWN", 0); err == nil {
		t.Fatal("encodeScalar should fail for unknown type")
	}
}

// TestParseBoolValue 布尔值解析
func TestParseBoolValue(t *testing.T) {
	trueCases := []string{"true", "TRUE", "1", "True"}
	for _, c := range trueCases {
		if v, _ := parseBoolValue(c); v != true {
			t.Fatalf("parseBoolValue(%q) want true", c)
		}
	}
	falseCases := []string{"false", "0", "FALSE"}
	for _, c := range falseCases {
		if v, _ := parseBoolValue(c); v != false {
			t.Fatalf("parseBoolValue(%q) want false", c)
		}
	}
	if _, err := parseBoolValue("abc"); err == nil {
		t.Fatal("parseBoolValue should fail for abc")
	}
}
