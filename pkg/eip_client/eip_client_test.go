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
	"errors"
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

// TestReadTags_TimeoutMarksRestBad: 第 k 个 tag 超时后,剩余 tag 直接标 bad,
// 不再各等一个超时窗口;输出条数必须与输入一致(超时点自身也要在结果里)。
func TestReadTags_TimeoutMarksRestBad(t *testing.T) {
	pts := []Point{
		{Name: "ok", Tag: "tag0", Type: "DINT"},
		{Name: "slow", Tag: "tag1", Type: "DINT"},
		{Name: "r0", Tag: "tag2", Type: "DINT"},
		{Name: "r1", Tag: "tag3", Type: "DINT"},
	}
	calls := 0
	got, err := readTags(pts, func(tag, typ string) (interface{}, error) {
		calls++
		if tag == "tag1" {
			return nil, errors.New("read tcp 10.0.0.2:44818: i/o timeout")
		}
		return calls, nil
	}, nil)

	assert.Nil(t, err)
	assert.Equal(t, 4, len(got), "输出条数必须与输入一致")
	assert.Equal(t, 2, calls, "超时后不应继续读后续 tag")
	assert.Equal(t, "good", got[0].Quality)
	assert.Equal(t, pts[0].Name, got[0].Name)
	assert.Equal(t, "bad", got[1].Quality)
	assert.Equal(t, pts[1].Name, got[1].Name)
	assert.Equal(t, "bad", got[2].Quality)
	assert.Equal(t, pts[2].Name, got[2].Name)
	assert.Equal(t, "bad", got[3].Quality)
	assert.Equal(t, pts[3].Name, got[3].Name)
}

// TestReadTags_AllTimeoutReturnsError: 全部失败时返回聚合错误(连接级)。
func TestReadTags_AllTimeoutReturnsError(t *testing.T) {
	pts := []Point{{Name: "a", Tag: "t0"}, {Name: "b", Tag: "t1"}}
	got, err := readTags(pts, func(tag, typ string) (interface{}, error) {
		return nil, errors.New("i/o timeout")
	}, nil)

	assert.NotNil(t, err)
	assert.Equal(t, 2, len(got))
}

// TestReadTags_NonTimeoutErrorContinues: 非超时错误(单个 tag 坏)不短路,后续 tag 照常读。
func TestReadTags_NonTimeoutErrorContinues(t *testing.T) {
	pts := []Point{{Name: "a", Tag: "t0"}, {Name: "b", Tag: "t1"}}
	got, err := readTags(pts, func(tag, typ string) (interface{}, error) {
		if tag == "t0" {
			return nil, errors.New("tag not found")
		}
		return 7, nil
	}, nil)

	assert.Nil(t, err)
	assert.Equal(t, "bad", got[0].Quality)
	assert.Equal(t, "good", got[1].Quality)
	assert.Equal(t, 7, got[1].Value)
}
