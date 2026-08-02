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

// Package dlt645 provides self-implemented frame encoding/decoding and collection nodes for DL/T 645-2007 multi-function energy meter communication protocol.
//
// Frame format (request frame, master→meter):
//
//	0x68 | A0-A5(6-byte BCD address, low-byte-first) | 0x68 | C(control code) | L(data length) | DATA(each byte+0x33) | CS | 0x16
//
// CS is arithmetic sum low 8 bits from frame start to data field end. Read data control code 0x11, normal response 0x91, error response 0xD1.
// Data ID DI configuration follows standard writing order "DI3-DI2-DI1-DI0" (high-byte-first, e.g. "02-01-01-00"),
// transmitted in wire order reversed to low-byte-first.
package dlt645

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	frameStart  = 0x68 // frame start/address separator
	frameEnd    = 0x16 // frame end
	ctrlRead    = 0x11 // master read data
	ctrlWrite   = 0x14 // master write data
	respMask    = 0x80 // control code D7: slave response flag
	errMask     = 0x40 // control code D6: error response flag
	dataMask    = 0x33 // data field transmission mask
	addrLen     = 6    // address field bytes
	diLen       = 4    // data ID bytes
	minFrameLen = 12   // minimum frame length: 68+A(6)+68+C+L+CS+16
)

// Error response codes
var errCodes = map[byte]string{
	0x01: "other error",
	0x02: "rate count exceeded",
	0x03: "no data",
	0x04: "permission denied",
}

// Checksum calculates CS: arithmetic sum low 8 bits of all bytes.
func Checksum(b []byte) byte {
	var sum byte
	for _, c := range b {
		sum += c
	}
	return sum
}

// EncodeBCD encodes v to n-byte BCD (high-digit in high-byte, high-byte padding with zeros).
func EncodeBCD(v uint64, n int) []byte {
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		lo := byte(v % 10)
		v /= 10
		hi := byte(v % 10)
		v /= 10
		out[i] = hi<<4 | lo
	}
	return out
}

// DecodeBCD decodes BCD bytes (high-digit in high-byte) to unsigned integer.
func DecodeBCD(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v*100 + uint64(c>>4)*10 + uint64(c&0x0F)
	}
	return v
}

// ParseAddr parses 12-digit decimal meter address string (e.g. "000000000001", left-padded with 0) to
// 6-byte address field (A0 low-byte-first).
func ParseAddr(addr string) ([]byte, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("dlt645: empty meter address")
	}
	if len(addr) > addrLen*2 {
		return nil, fmt.Errorf("dlt645: meter address %q exceeds 12 digits", addr)
	}
	for _, c := range addr {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("dlt645: meter address %q has non-digit", addr)
		}
	}
	// Left-pad odd-length address to even so the leading digit is parsed, not silently dropped.
	if len(addr)%2 != 0 {
		addr = "0" + addr
	}
	out := make([]byte, addrLen)
	// From ones place every two digits per byte, low-byte-first
	for i, pos := 0, len(addr)-2; i < addrLen; i, pos = i+1, pos-2 {
		if pos >= 0 {
			out[i] = (addr[pos]-'0')<<4 | (addr[pos+1] - '0')
		}
	}
	return out, nil
}

// FormatAddr formats 6-byte address field (A0 low-byte-first) to 12-digit decimal string.
func FormatAddr(addr []byte) string {
	var sb strings.Builder
	for i := len(addr) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%02X", addr[i])
	}
	return sb.String()
}

// ParseDI parses data ID string ("DI3-DI2-DI1-DI0" standard writing order or continuous 8-digit hex, e.g.
// "02-01-01-00"/"02010100") to wire-order bytes [DI0,DI1,DI2,DI3] (low-byte-first).
func ParseDI(s string) ([diLen]byte, error) {
	var di [diLen]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != diLen*2 {
		return di, fmt.Errorf("dlt645: invalid DI %q, expect DI3-DI2-DI1-DI0", s)
	}
	hi, err := hex.DecodeString(clean)
	if err != nil {
		return di, fmt.Errorf("dlt645: invalid DI %q: %v", s, err)
	}
	// Writing order DI3..DI0 -> wire order DI0..DI3
	for i := 0; i < diLen; i++ {
		di[i] = hi[diLen-1-i]
	}
	return di, nil
}

// FormatDI formats wire-order DI to standard writing string "DI3-DI2-DI1-DI0".
func FormatDI(di [diLen]byte) string {
	return fmt.Sprintf("%02X-%02X-%02X-%02X", di[3], di[2], di[1], di[0])
}

// BuildReadFrame constructs read data request frame (control code 0x11, data field is 4-byte DI).
func BuildReadFrame(addr string, di []byte) ([]byte, error) {
	if len(di) != diLen {
		return nil, fmt.Errorf("dlt645: DI length %d, expect 4", len(di))
	}
	addrBytes, err := ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	return buildFrame(addrBytes, ctrlRead, di), nil
}

// BuildWriteFrame constructs write data request frame (control code 0x14, data field is DI + data to write).
func BuildWriteFrame(addr string, di, data []byte) ([]byte, error) {
	if len(di) != diLen {
		return nil, fmt.Errorf("dlt645: DI length %d, expect 4", len(di))
	}
	addrBytes, err := ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, diLen+len(data))
	payload = append(payload, di...)
	payload = append(payload, data...)
	return buildFrame(addrBytes, ctrlWrite, payload), nil
}

// buildFrame assembles complete frame: data field each byte +0x33, appends CS and 0x16.
func buildFrame(addrBytes []byte, ctrl byte, payload []byte) []byte {
	frame := make([]byte, 0, minFrameLen+len(payload))
	frame = append(frame, frameStart)
	frame = append(frame, addrBytes...)
	frame = append(frame, frameStart, ctrl, byte(len(payload)))
	for _, b := range payload {
		frame = append(frame, b+dataMask)
	}
	frame = append(frame, Checksum(frame), frameEnd)
	return frame
}

// parseFrame parses complete frame, returns control code, address field, data field (each byte -0x33 restored).
// Verifies frame structure (length/start/end) and CS.
func parseFrame(frame []byte) (ctrl byte, addr, payload []byte, err error) {
	if len(frame) < minFrameLen {
		return 0, nil, nil, fmt.Errorf("dlt645: frame too short (%d bytes)", len(frame))
	}
	if frame[0] != frameStart {
		return 0, nil, nil, fmt.Errorf("dlt645: invalid frame start 0x%02X", frame[0])
	}
	if frame[7] != frameStart {
		return 0, nil, nil, fmt.Errorf("dlt645: invalid address separator 0x%02X", frame[7])
	}
	l := int(frame[9])
	if len(frame) != minFrameLen+l {
		return 0, nil, nil, fmt.Errorf("dlt645: frame length %d mismatch data length %d", len(frame), l)
	}
	if frame[len(frame)-1] != frameEnd {
		return 0, nil, nil, fmt.Errorf("dlt645: invalid frame end 0x%02X", frame[len(frame)-1])
	}
	if cs := Checksum(frame[:len(frame)-2]); cs != frame[len(frame)-2] {
		return 0, nil, nil, fmt.Errorf("dlt645: checksum mismatch: got 0x%02X, want 0x%02X", frame[len(frame)-2], cs)
	}
	raw := frame[10 : 10+l]
	payload = make([]byte, l)
	for i, b := range raw {
		payload[i] = b - dataMask
	}
	return frame[8], frame[1:7], payload, nil
}

// ParseResponse parses slave response frame, returns DI and response data (already -0x33).
// Non-slave response frames and error responses (control code D6=1, data field is ERR error code) return error.
func ParseResponse(frame []byte) (di, data []byte, err error) {
	ctrl, _, payload, err := parseFrame(frame)
	if err != nil {
		return nil, nil, err
	}
	if ctrl&respMask == 0 {
		return nil, nil, fmt.Errorf("dlt645: not a slave response (ctrl=0x%02X)", ctrl)
	}
	if ctrl&errMask != 0 {
		code := byte(0)
		if len(payload) > 0 {
			code = payload[0]
		}
		msg := errCodes[code]
		if msg == "" {
			msg = "unknown"
		}
		return nil, nil, fmt.Errorf("dlt645: abnormal response ERR=0x%02X (%s)", code, msg)
	}
	if len(payload) < diLen {
		return nil, nil, fmt.Errorf("dlt645: response data too short (%d bytes)", len(payload))
	}
	return payload[:diLen], payload[diLen:], nil
}
