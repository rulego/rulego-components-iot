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
	"errors"
	"fmt"
	"math"
	"unicode/utf16"
)

// BACnet application data tag numbers (ASHRAE 135 section 20.2).
const (
	AppTagNull             uint8 = 0
	AppTagBoolean          uint8 = 1
	AppTagUnsignedInt      uint8 = 2
	AppTagSignedInt        uint8 = 3
	AppTagReal             uint8 = 4
	AppTagDouble           uint8 = 5
	AppTagOctetString      uint8 = 6
	AppTagCharacterString  uint8 = 7
	AppTagBitString        uint8 = 8
	AppTagEnumerated       uint8 = 9
	AppTagDate             uint8 = 10
	AppTagTime             uint8 = 11
	AppTagObjectIdentifier uint8 = 12
)

// DecodeApplication decodes one BACnet application-tagged value starting at b[0].
// Returns the decoded Go value and the number of bytes consumed (tag + extended-length bytes + data).
// Boolean encodes its value in the length field (no data bytes); other types read length-prefixed data.
func DecodeApplication(b []byte) (interface{}, int, error) {
	if len(b) == 0 {
		return nil, 0, errors.New("bacnet: empty application data")
	}
	tagNumber := b[0] >> 4
	lvt := b[0] & 0x07

	// Boolean: value in length field, no data bytes.
	if tagNumber == AppTagBoolean {
		return lvt != 0, 1, nil
	}

	dataLen, hdrLen, err := decodeLength(lvt, b)
	if err != nil {
		return nil, 0, err
	}
	if len(b) < hdrLen+dataLen {
		return nil, 0, fmt.Errorf("bacnet: short data (%d bytes) for tag %d", len(b)-hdrLen, tagNumber)
	}
	data := b[hdrLen : hdrLen+dataLen]
	consumed := hdrLen + dataLen

	switch tagNumber {
	case AppTagNull:
		return nil, consumed, nil
	case AppTagUnsignedInt, AppTagEnumerated:
		return decodeUnsigned(data), consumed, nil
	case AppTagSignedInt:
		return decodeSigned(data), consumed, nil
	case AppTagReal:
		if dataLen != 4 {
			return nil, 0, fmt.Errorf("bacnet: real length %d != 4", dataLen)
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(data))), consumed, nil
	case AppTagDouble:
		if dataLen != 8 {
			return nil, 0, fmt.Errorf("bacnet: double length %d != 8", dataLen)
		}
		return math.Float64frombits(binary.BigEndian.Uint64(data)), consumed, nil
	case AppTagCharacterString:
		s, err := decodeCharacterString(data)
		if err != nil {
			return nil, 0, err
		}
		return s, consumed, nil
	case AppTagOctetString, AppTagDate, AppTagTime:
		out := make([]byte, len(data))
		copy(out, data)
		return out, consumed, nil
	case AppTagBitString:
		return decodeBitString(data), consumed, nil
	case AppTagObjectIdentifier:
		if dataLen != 4 {
			return nil, 0, fmt.Errorf("bacnet: object-identifier length %d != 4", dataLen)
		}
		v := binary.BigEndian.Uint32(data)
		return ObjectIdentifier{Type: uint16(v >> 22), Instance: v & 0x3FFFFF}, consumed, nil
	}
	return nil, 0, fmt.Errorf("bacnet: unsupported application tag %d", tagNumber)
}

// decodeLength resolves the data length and header length from the 3-bit lengthValueType (LVT),
// the low 3 bits of a BACnet tag octet (ASHRAE 135 §20.2.1.1.2).
// hdrLen counts the 1 tag byte plus any extended-length bytes; data follows at b[hdrLen:].
//
//	lvt 0-4: the LVT itself is the data length (inline).
//	lvt 5:   "extended value". The next byte is the length, with two escape codes:
//	           - 0xFE (254): the next 2 bytes (big-endian uint16) are the length.
//	           - 0xFF (255): the next 4 bytes (big-endian uint32) are the length.
//	         any other value (0-253) is a 1-byte length.
//
// lvt 6 and 7 are opening/closing tags (handled by callers) and must not reach here.
func decodeLength(lvt uint8, b []byte) (dataLen int, hdrLen int, err error) {
	switch lvt {
	case 0, 1, 2, 3, 4:
		return int(lvt), 1, nil
	case 5:
		if len(b) < 2 {
			return 0, 0, errors.New("bacnet: short extended length")
		}
		switch b[1] {
		default: // 0-253: 1-byte length
			return int(b[1]), 2, nil
		case 0xFE: // 254: uint16 length follows
			if len(b) < 4 {
				return 0, 0, errors.New("bacnet: short uint16 length")
			}
			return int(binary.BigEndian.Uint16(b[2:4])), 4, nil
		case 0xFF: // 255: uint32 length follows
			if len(b) < 6 {
				return 0, 0, errors.New("bacnet: short uint32 length")
			}
			return int(binary.BigEndian.Uint32(b[2:6])), 6, nil
		}
	}
	// lvt 6 (opening tag) / 7 (closing tag) are not lengths.
	return 0, 0, fmt.Errorf("bacnet: length value type %d is not a data length", lvt)
}

func decodeUnsigned(data []byte) uint64 {
	var v uint64
	for _, b := range data {
		v = v<<8 | uint64(b)
	}
	return v
}

func decodeSigned(data []byte) int64 {
	var v int64
	for _, b := range data {
		v = v<<8 | int64(b)
	}
	// Arithmetic sign-extension from len(data) bytes to int64.
	shift := uint((8 - len(data)) * 8)
	return (v << shift) >> shift
}

// decodeCharacterString decodes a BACnet character string. First data byte is the encoding:
// 0=ANSI X3.4, 3=UCS-2 BE, 4=ISO 10646 (UTF-8), others returned as a best-effort raw string.
func decodeCharacterString(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("bacnet: empty character string")
	}
	enc := data[0]
	rest := data[1:]
	switch enc {
	case 0, 4:
		return string(rest), nil
	case 3: // UCS-2 BE
		if len(rest)%2 != 0 {
			return "", fmt.Errorf("bacnet: UCS-2 string with odd byte length %d", len(rest))
		}
		u := make([]uint16, len(rest)/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(rest[i*2:])
		}
		return string(utf16.Decode(u)), nil
	default:
		return string(rest), nil
	}
}

// decodeBitString decodes a BACnet bit string: first byte = unused bits in the last byte.
func decodeBitString(data []byte) []bool {
	if len(data) == 0 {
		return nil
	}
	unused := int(data[0])
	bits := make([]bool, 0, len(data)*8)
	for _, b := range data[1:] {
		for i := 7; i >= 0; i-- {
			bits = append(bits, b&(1<<i) != 0)
		}
	}
	if unused < len(bits) {
		bits = bits[:len(bits)-unused]
	}
	return bits
}

// EncodeApplication encodes a Go value with the given application tag to BACnet bytes.
func EncodeApplication(tag uint8, value interface{}) ([]byte, error) {
	switch tag {
	case AppTagNull:
		return []byte{AppTagNull << 4}, nil
	case AppTagBoolean:
		if v, err := toBool(value); err != nil {
			return nil, err
		} else if v {
			return []byte{AppTagBoolean<<4 | 1}, nil
		}
		return []byte{AppTagBoolean << 4}, nil
	case AppTagUnsignedInt, AppTagEnumerated:
		n, err := toUint64(value)
		if err != nil {
			return nil, err
		}
		return encodeTagged(tag, encodeUnsigned(n)), nil
	case AppTagSignedInt:
		n, err := toInt64(value)
		if err != nil {
			return nil, err
		}
		return encodeTagged(tag, encodeSigned(n)), nil
	case AppTagReal:
		f, err := toFloat64(value)
		if err != nil {
			return nil, err
		}
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, math.Float32bits(float32(f)))
		return encodeTagged(tag, data), nil
	case AppTagDouble:
		f, err := toFloat64(value)
		if err != nil {
			return nil, err
		}
		data := make([]byte, 8)
		binary.BigEndian.PutUint64(data, math.Float64bits(f))
		return encodeTagged(tag, data), nil
	case AppTagCharacterString:
		s, err := toString(value)
		if err != nil {
			return nil, err
		}
		data := make([]byte, 1+len(s))
		data[0] = 4 // ISO 10646 UTF-8
		copy(data[1:], s)
		return encodeTagged(tag, data), nil
	case AppTagOctetString, AppTagDate, AppTagTime:
		// These are encoded as raw octets. Accept []byte or string (utf-8 bytes).
		data, err := toBytes(value)
		if err != nil {
			return nil, err
		}
		return encodeTagged(tag, data), nil
	}
	return nil, fmt.Errorf("bacnet: cannot encode application tag %d", tag)
}

// encodeTagged wraps data with an application tag byte and the ASHRAE 135 §20.2.1.1.2
// length encoding: inline (length 0-4), 1-byte length (5-253), 2-byte length via 0xFE (254-65535),
// or 4-byte length via 0xFF (>= 65536).
func encodeTagged(tag uint8, data []byte) []byte {
	dl := len(data)
	switch {
	case dl <= 4:
		out := make([]byte, 1+dl)
		out[0] = tag<<4 | byte(dl)
		copy(out[1:], data)
		return out
	case dl <= 253:
		out := make([]byte, 2+dl)
		out[0] = tag<<4 | 5
		out[1] = byte(dl)
		copy(out[2:], data)
		return out
	case dl <= 0xFFFF:
		out := make([]byte, 4+dl)
		out[0] = tag<<4 | 5
		out[1] = 0xFE
		binary.BigEndian.PutUint16(out[2:4], uint16(dl))
		copy(out[4:], data)
		return out
	default:
		out := make([]byte, 6+dl)
		out[0] = tag<<4 | 5
		out[1] = 0xFF
		binary.BigEndian.PutUint32(out[2:6], uint32(dl))
		copy(out[6:], data)
		return out
	}
}

func encodeUnsigned(n uint64) []byte {
	switch {
	case n <= 0xff:
		return []byte{byte(n)}
	case n <= 0xffff:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(n))
		return b
	case n <= 0xffffff:
		return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(n))
		return b
	}
}

func encodeSigned(n int64) []byte {
	switch {
	case n >= -128 && n <= 127:
		return []byte{byte(n)}
	case n >= -32768 && n <= 32767:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(int16(n)))
		return b
	case n >= -(1<<23) && n <= (1<<23)-1:
		return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(int32(n)))
		return b
	}
}

func toBool(v interface{}) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case uint64:
		return x != 0, nil
	case int64:
		return x != 0, nil
	case float64:
		return x != 0, nil
	}
	return false, fmt.Errorf("bacnet: cannot use %T as bool", v)
}

func toUint64(v interface{}) (uint64, error) {
	switch x := v.(type) {
	case uint64:
		return x, nil
	case int64:
		return uint64(x), nil
	case float64:
		return uint64(x), nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	}
	return 0, fmt.Errorf("bacnet: cannot use %T as unsigned", v)
}

func toInt64(v interface{}) (int64, error) {
	switch x := v.(type) {
	case int64:
		return x, nil
	case uint64:
		return int64(x), nil
	case float64:
		return int64(x), nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	}
	return 0, fmt.Errorf("bacnet: cannot use %T as signed", v)
}

func toFloat64(v interface{}) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case int64:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	}
	return 0, fmt.Errorf("bacnet: cannot use %T as float", v)
}

func toString(v interface{}) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case []byte:
		return string(x), nil
	}
	return "", fmt.Errorf("bacnet: cannot use %T as string", v)
}

func toBytes(v interface{}) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case string:
		return []byte(x), nil
	}
	return nil, fmt.Errorf("bacnet: cannot use %T as []byte", v)
}
