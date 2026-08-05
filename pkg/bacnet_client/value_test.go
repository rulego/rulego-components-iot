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

package bacnetclient

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// Decode expectations are derived from ASHRAE 135 application data encoding, not from the implementation.
func TestDecodeApplication(t *testing.T) {
	cases := []struct {
		name     string
		in       []byte
		want     interface{}
		consumed int
	}{
		{"real 1.5", []byte{0x44, 0x3F, 0xC0, 0x00, 0x00}, float64(1.5), 5},
		{"bool true", []byte{0x11}, true, 1},
		{"bool false", []byte{0x10}, false, 1},
		{"uint 100", []byte{0x21, 0x64}, uint64(100), 2},
		{"uint 300", []byte{0x22, 0x01, 0x2C}, uint64(300), 3},
		{"uint 0", []byte{0x20}, uint64(0), 1},
		{"enum 3", []byte{0x91, 0x03}, uint64(3), 2},
		{"signed -1", []byte{0x31, 0xFF}, int64(-1), 2},
		{"signed 127", []byte{0x31, 0x7F}, int64(127), 2},
		{"double 1.5", []byte{0x55, 0x08, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, float64(1.5), 10},
		{"string hi ansi", []byte{0x73, 0x00, 0x68, 0x69}, "hi", 4},
		{"string hello ext", []byte{0x75, 0x06, 0x00, 'h', 'e', 'l', 'l', 'o'}, "hello", 8},
		{"null", []byte{0x00}, nil, 1},
		{"objid ai1", []byte{0xC4, 0x00, 0x00, 0x00, 0x01}, ObjectIdentifier{Type: 0, Instance: 1}, 5},
		{"objid device 100", []byte{0xC4, 0x02, 0x00, 0x00, 0x64}, ObjectIdentifier{Type: 8, Instance: 100}, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, consumed, err := DecodeApplication(c.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if consumed != c.consumed {
				t.Errorf("consumed = %d, want %d", consumed, c.consumed)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("value = %v (%T), want %v (%T)", got, got, c.want, c.want)
			}
		})
	}
}

func TestEncodeApplication(t *testing.T) {
	cases := []struct {
		name string
		tag  uint8
		val  interface{}
		want []byte
	}{
		{"real 1.5", AppTagReal, float64(1.5), []byte{0x44, 0x3F, 0xC0, 0x00, 0x00}},
		{"bool true", AppTagBoolean, true, []byte{0x11}},
		{"bool false", AppTagBoolean, false, []byte{0x10}},
		{"enum 3", AppTagEnumerated, uint64(3), []byte{0x91, 0x03}},
		{"uint 100", AppTagUnsignedInt, uint64(100), []byte{0x21, 0x64}},
		{"string hi", AppTagCharacterString, "hi", []byte{0x73, 0x04, 0x68, 0x69}},
		{"double 1.5", AppTagDouble, float64(1.5), []byte{0x55, 0x08, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"null", AppTagNull, nil, []byte{0x00}},
		{"signed -1", AppTagSignedInt, int64(-1), []byte{0x31, 0xFF}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EncodeApplication(c.tag, c.val)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %x, want %x", got, c.want)
			}
		})
	}
}

// Round-trip: encode then decode must recover an equivalent value.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		tag  uint8
		val  interface{}
	}{
		{"real", AppTagReal, float64(23.75)},
		{"bool true", AppTagBoolean, true},
		{"bool false", AppTagBoolean, false},
		{"uint", AppTagUnsignedInt, uint64(4660)},
		{"enum", AppTagEnumerated, uint64(7)},
		{"signed neg", AppTagSignedInt, int64(-42)},
		{"signed pos", AppTagSignedInt, int64(9000)},
		{"string short", AppTagCharacterString, "OK"},
		{"string long", AppTagCharacterString, "supply-air-temp sensor"},
		{"double", AppTagDouble, math.Pi},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc, err := EncodeApplication(c.tag, c.val)
			if err != nil {
				t.Fatalf("encode error: %v", err)
			}
			got, consumed, err := DecodeApplication(enc)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(enc) {
				t.Errorf("consumed %d != encoded length %d", consumed, len(enc))
			}
			if !valuesEqual(got, c.val) {
				t.Errorf("round-trip got %v (%T), want %v (%T)", got, got, c.val, c.val)
			}
		})
	}
}

// TestExtendedLength exercises the ASHRAE 135 §20.2.1.1.2 extended-length encoding at every
// boundary: data lengths 5-253 (1-byte length), 254-65535 (0xFE + uint16), and 65536+
// (0xFF + uint32). Uses an octet-string (tag 6) so the data length equals n exactly.
// This guards the decodeLength/encodeTagged rewrite.
func TestExtendedLength(t *testing.T) {
	for _, n := range []int{4, 5, 252, 253, 254, 255, 256, 1023, 1024, 65535, 65536, 65537, 70000} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			data := []byte(strings.Repeat("x", n))
			enc, err := EncodeApplication(AppTagOctetString, data)
			if err != nil {
				t.Fatalf("encode error: %v", err)
			}
			// Verify the tag byte and length prefix match the spec for this size class.
			switch {
			case n <= 4:
				if enc[0]&0x07 != byte(n) {
					t.Errorf("inline length tag byte %02x, want lvt %d", enc[0], n)
				}
			case n <= 253:
				if enc[0]&0x07 != 5 || enc[1] != byte(n) {
					t.Errorf("1-byte extended length %02x %02x, want 05 %02x", enc[0], enc[1], n)
				}
			case n <= 65535:
				want := uint16(n)
				if enc[0]&0x07 != 5 || enc[1] != 0xFE || binary.BigEndian.Uint16(enc[2:4]) != want {
					t.Errorf("uint16 length prefix %02x %02x %02x %02x, want 05 FE %04x", enc[0], enc[1], enc[2], enc[3], want)
				}
			default:
				want := uint32(n)
				if enc[0]&0x07 != 5 || enc[1] != 0xFF || binary.BigEndian.Uint32(enc[2:6]) != want {
					t.Errorf("uint32 length prefix, want 05 FF %08x", want)
				}
			}
			got, consumed, err := DecodeApplication(enc)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(enc) {
				t.Errorf("consumed = %d, want %d", consumed, len(enc))
			}
			if gb, _ := got.([]byte); len(gb) != n {
				t.Errorf("round-trip length %d, got %d", n, len(gb))
			}
		})
	}
}

// TestCharacterStringEncodings checks the character-string encoding selector, including that a
// malformed UCS-2 (odd byte count) is rejected rather than silently garbled.
func TestCharacterStringEncodings(t *testing.T) {
	// ANSI: lvt=3 inline, data = enc(0x00) + "hi" = 3 bytes
	if v, _, err := DecodeApplication([]byte{0x73, 0x00, 'h', 'i'}); err != nil || v != "hi" {
		t.Errorf("ANSI decode = %q %v, want hi", v, err)
	}
	// UTF-8: lvt=3 inline, data = enc(0x04) + "hi" = 3 bytes
	if v, _, err := DecodeApplication([]byte{0x73, 0x04, 'h', 'i'}); err != nil || v != "hi" {
		t.Errorf("UTF-8 decode = %q %v, want hi", v, err)
	}
	// UCS-2 BE: "AB" = 0x0041 0x0042. lvt=5 (extended), length byte=5, data = enc(0x03) + 4 UCS-2 bytes
	ucs2 := []byte{0x75, 0x05, 0x03, 0x00, 0x41, 0x00, 0x42}
	if v, _, err := DecodeApplication(ucs2); err != nil || v != "AB" {
		t.Errorf("UCS-2 decode = %q %v, want AB", v, err)
	}
	// Malformed UCS-2: odd byte count must error. lvt=4 inline, data = enc(0x03) + 3 odd bytes
	bad := []byte{0x74, 0x03, 0x00, 0x41, 0x42}
	if _, _, err := DecodeApplication(bad); err == nil {
		t.Error("expected error for odd-length UCS-2 string, got nil")
	}
}

func valuesEqual(a, b interface{}) bool {
	// Reals: tolerate float32 precision loss in real round-trip.
	if af, aok := a.(float64); aok {
		if bf, bok := b.(float64); bok {
			return math.Abs(af-bf) < 1e-6 || af == bf
		}
	}
	return reflect.DeepEqual(a, b)
}

func TestParseObjectType(t *testing.T) {
	cases := map[string]uint16{
		"analog-input": 0, "ai": 0, "AI": 0, "0": 0,
		"binary-output": 4, "bo": 4,
		"multi-state-value": 19, "msv": 19,
		"device": 8,
	}
	for in, want := range cases {
		got, err := ParseObjectType(in)
		if err != nil || got != want {
			t.Errorf("ParseObjectType(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := ParseObjectType("nonsense"); err == nil {
		t.Error("expected error for unknown object type")
	}
}

func TestParseProperty(t *testing.T) {
	cases := map[string]uint32{
		"present-value": 85, "pv": 85, "85": 85,
		"description": 28, "object-name": 77, "units": 117,
		// Property identifiers above 255 (proprietary range) must parse too.
		"512": 512, "9999": 9999,
	}
	for in, want := range cases {
		got, err := ParseProperty(in)
		if err != nil || got != want {
			t.Errorf("ParseProperty(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := ParseProperty("nope"); err == nil {
		t.Error("expected error for unknown property")
	}
}
