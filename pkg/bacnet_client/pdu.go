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
)

// BACnet/IP and APDU framing constants.
const (
	bvlcType        = 0x81
	bvlcFuncUnicast = 0x0a
	npduVersion     = 0x01
	npduControlReq  = 0x04 // data-expecting-reply bit (request)

	// max-APDU-length-accepted code sent in confirmed requests.
	// ASHRAE 135 §20.1.2.4: 0x05 = up to 1476 octets (the BACnet/IP maximum, fits one Ethernet frame).
	maxAPDULenCode = 0x05

	// APDU PDU types (high nibble of the first APDU octet).
	pduConfirmedReq = 0x0
	pduComplexAck   = 0x3
	pduSimpleAck    = 0x2
	pduError        = 0x4
	pduReject       = 0x5
	pduAbort        = 0x6

	// confirmed service choices.
	svcReadProperty  = 0x0c
	svcWriteProperty = 0x0f

	ctxClassBit = 0x08 // tag class bit: set => context tag
	ctxOpenLow  = 0x0E // opening tag low nibble (class=1, lvt=6)
	ctxCloseLow = 0x0F // closing tag low nibble (class=1, lvt=7)
)

var (
	errShortFrame  = errors.New("bacnet: short frame")
	errBadBVLC     = errors.New("bacnet: not a BACnet/IP frame")
	errBadNPDU     = errors.New("bacnet: bad NPDU")
	errUnexpected  = errors.New("bacnet: unexpected response type")
	errNoValue     = errors.New("bacnet: no application value in response")
)

// buildFrame wraps a request APDU with NPDU (Original-Unicast, data-expecting-reply) and BVLC headers.
func buildFrame(apdu []byte) []byte {
	return buildFrameCtrl(apdu, npduControlReq)
}

// buildResponseFrame wraps a response APDU (ComplexACK/SimpleACK/Error/...) with an NPDU whose
// data-expecting-reply bit is clear (a response never expects a further reply) and a BVLC header.
func buildResponseFrame(apdu []byte) []byte {
	return buildFrameCtrl(apdu, 0x00)
}

func buildFrameCtrl(apdu []byte, control byte) []byte {
	total := 4 + 2 + len(apdu)
	frame := make([]byte, 4, total)
	frame[0] = bvlcType
	frame[1] = bvlcFuncUnicast
	binary.BigEndian.PutUint16(frame[2:4], uint16(total))
	frame = append(frame, npduVersion, control)
	frame = append(frame, apdu...)
	return frame
}

// confirmedReqAPDU builds a non-segmented confirmed-request APDU: type|maxAPDU|invokeID|service + payload.
func confirmedReqAPDU(invokeID, service uint8, payload []byte) []byte {
	apdu := make([]byte, 4, 4+len(payload))
	apdu[0] = pduConfirmedReq << 4
	apdu[1] = maxAPDULenCode
	apdu[2] = invokeID
	apdu[3] = service
	apdu = append(apdu, payload...)
	return apdu
}

func openingTag(tagNum uint8) byte { return tagNum<<4 | ctxOpenLow }
func closingTag(tagNum uint8) byte { return tagNum<<4 | ctxCloseLow }

// encodeContextEnumerated encodes a context-tagged enumerated/unsigned value (tag + data) of
// any length, following the same ASHRAE 135 length-encoding rules as application tags.
func encodeContextEnumerated(tagNum uint8, value uint64) []byte {
	data := encodeUnsignedBytes(value)
	return encodeTaggedContext(tagNum, data)
}

// encodeTaggedContext wraps data with a context-class tag byte (and extended length when > 4 bytes).
func encodeTaggedContext(tagNum uint8, data []byte) []byte {
	dl := len(data)
	switch {
	case dl <= 4:
		out := make([]byte, 1+dl)
		out[0] = tagNum<<4 | ctxClassBit | byte(dl)
		copy(out[1:], data)
		return out
	case dl <= 253:
		out := make([]byte, 2+dl)
		out[0] = tagNum<<4 | ctxClassBit | 5
		out[1] = byte(dl)
		copy(out[2:], data)
		return out
	case dl <= 0xFFFF:
		out := make([]byte, 4+dl)
		out[0] = tagNum<<4 | ctxClassBit | 5
		out[1] = 0xFE
		binary.BigEndian.PutUint16(out[2:4], uint16(dl))
		copy(out[4:], data)
		return out
	default:
		out := make([]byte, 6+dl)
		out[0] = tagNum<<4 | ctxClassBit | 5
		out[1] = 0xFF
		binary.BigEndian.PutUint32(out[2:6], uint32(dl))
		copy(out[6:], data)
		return out
	}
}

// encodeUnsignedBytes encodes v in the minimum number of big-endian bytes (no leading zero bytes),
// matching BACnet unsigned/enumerated encoding (ASHRAE 135 §20.2.6).
func encodeUnsignedBytes(v uint64) []byte {
	switch {
	case v == 0:
		return []byte{0}
	case v <= 0xFF:
		return []byte{byte(v)}
	case v <= 0xFFFF:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v))
		return b
	case v <= 0xFFFFFF:
		return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		// trim leading zero bytes
		i := 0
		for i < len(b)-1 && b[i] == 0 {
			i++
		}
		return b[i:]
	}
}

// parseContextObjectIdentifier reads a context-tagged ObjectIdentifier (tag + 4 bytes) at b[0].
func parseContextObjectIdentifier(b []byte, tagNum uint8) (ObjectIdentifier, int, error) {
	if len(b) < 5 || b[0] != tagNum<<4|ctxClassBit|0x04 {
		return ObjectIdentifier{}, 0, fmt.Errorf("bacnet: expected context tag %d object-identifier", tagNum)
	}
	oid := binary.BigEndian.Uint32(b[1:5])
	return ObjectIdentifier{Type: uint16(oid >> 22), Instance: oid & 0x3FFFFF}, 5, nil
}

// parseContextUint reads a context-tagged unsigned integer of any encoded length at b[0].
// The value is big-endian over its data bytes (BACnet unsigned/enumerated layout).
func parseContextUint(b []byte, tagNum uint8) (uint64, int, error) {
	if len(b) < 1 || b[0]>>4 != tagNum || b[0]&ctxClassBit == 0 {
		return 0, 0, fmt.Errorf("bacnet: expected context tag %d unsigned", tagNum)
	}
	lvt := b[0] & 0x07
	if lvt >= 6 {
		return 0, 0, fmt.Errorf("bacnet: context tag %d is an opening/closing tag", tagNum)
	}
	dataLen, hdrLen, err := decodeLength(lvt, b)
	if err != nil {
		return 0, 0, err
	}
	if len(b) < hdrLen+dataLen {
		return 0, 0, fmt.Errorf("bacnet: context tag %d short data", tagNum)
	}
	return decodeUnsignedBytes(b[hdrLen : hdrLen+dataLen]), hdrLen + dataLen, nil
}

// parseContextEnumerated reads a context-tagged enumerated value of any length at b[0].
// BACnet encodes enumerated and unsigned with the same octet layout.
func parseContextEnumerated(b []byte, tagNum uint8) (uint32, int, error) {
	v, n, err := parseContextUint(b, tagNum)
	if err != nil {
		return 0, 0, err
	}
	return uint32(v), n, nil
}

// isContextTag reports whether b[0] is a context-class tag with the given tag number.
func isContextTag(b0, tagNum byte) bool {
	return b0&ctxClassBit != 0 && b0>>4 == tagNum
}

func decodeUnsignedBytes(data []byte) uint64 {
	var v uint64
	for _, b := range data {
		v = v<<8 | uint64(b)
	}
	return v
}

// frameInfo holds the parsed APDU header of a frame.
type frameInfo struct {
	pduType        uint8 // raw high nibble
	invokeID       uint8
	service        uint8
	serviceRequest []byte // bytes after the APDU header
}

// parseResponse parses a BACnet/IP response frame (BVLC+NPDU+APDU) into its APDU header.
func parseResponse(frame []byte) (frameInfo, error) {
	info := frameInfo{}
	if len(frame) < 6 {
		return info, errShortFrame
	}
	if frame[0] != bvlcType {
		return info, errBadBVLC
	}
	off := 4 // skip BVLC
	if frame[off] != npduVersion {
		return info, errBadNPDU
	}
	off++
	control := frame[off]
	off++
	if control&0x80 != 0 { // DNET/DLEN/DADR/Hop present
		if off+4 > len(frame) {
			return info, errBadNPDU
		}
		off += 2 // DNET
		dlen := int(frame[off])
		off++ // DLEN
		if off+dlen+1 > len(frame) {
			return info, errBadNPDU
		}
		off += dlen // DADR
		off++       // Hop
	}
	if control&0x20 != 0 { // SNET/SLEN/SADR present
		if off+3 > len(frame) {
			return info, errBadNPDU
		}
		off += 2 // SNET
		slen := int(frame[off])
		off++ // SLEN
		if off+slen > len(frame) {
			return info, errBadNPDU
		}
		off += slen // SADR
	}
	if off >= len(frame) {
		return info, errShortFrame
	}
	info.pduType = frame[off] >> 4
	switch info.pduType {
	case pduComplexAck, pduSimpleAck, pduError, pduReject, pduAbort:
		if off+3 > len(frame) {
			return info, errShortFrame
		}
		info.invokeID = frame[off+1]
		info.service = frame[off+2]
		info.serviceRequest = frame[off+3:]
	default:
		return info, fmt.Errorf("bacnet: unsupported response PDU type %d", info.pduType)
	}
	return info, nil
}

// parseRequest parses a BACnet/IP confirmed-request frame (used by mock server).
func parseRequest(frame []byte) (frameInfo, error) {
	info := frameInfo{}
	if len(frame) < 8 {
		return info, errShortFrame
	}
	if frame[0] != bvlcType {
		return info, errBadBVLC
	}
	off := 4
	if frame[off] != npduVersion {
		return info, errBadNPDU
	}
	off += 2 // version + control (requests use no DNET/SNET)
	info.pduType = frame[off] >> 4
	if info.pduType != pduConfirmedReq {
		return info, fmt.Errorf("bacnet: expected confirmed request, got PDU type %d", info.pduType)
	}
	info.invokeID = frame[off+2]
	info.service = frame[off+3]
	info.serviceRequest = frame[off+4:]
	return info, nil
}

// scanValue locates and decodes the first application-tagged value in APDU service-request bytes,
// skipping context tags (including opening/closing tags). Used to read ReadProperty response values.
func scanValue(b []byte) (interface{}, error) {
	off := 0
	for off < len(b) {
		tagByte := b[off]
		if tagByte&ctxClassBit != 0 {
			lvt := tagByte & 0x07
			if lvt >= 6 { // opening(6)/closing(7): 1 byte, no data
				off++
				continue
			}
			dataLen, hdrLen, err := decodeLength(lvt, b[off:])
			if err != nil {
				return nil, err
			}
			off += hdrLen + dataLen
			continue
		}
		v, _, err := DecodeApplication(b[off:])
		return v, err
	}
	return nil, errNoValue
}
