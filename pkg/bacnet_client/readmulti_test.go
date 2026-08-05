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
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
	"time"
)

// rpmAckFrame builds a ReadPropertyMultiple-ACK frame from typed inputs using the ASHRAE 135
// §20.2.15 wire layout, independently of the client's request builders. The service-request body is:
//
//	for each object: [0] object-identifier, opening-tag 1, (
//	    [2] property-identifier, opening-tag 4, <app value>, closing-tag 4
//	  | [2] property-identifier, opening-tag 5, <class enum>, <code enum>, closing-tag 5
//	), closing-tag 1
func rpmAckFrame(invokeID uint8, objs ...rpmObject) []byte {
	apdu := []byte{pduComplexAck << 4, invokeID, svcReadPropMultiple}
	for _, o := range objs {
		apdu = append(apdu, 0x0C)
		apdu = append(apdu, oidBytes(o.oid.Type, o.oid.Instance)...)
		apdu = append(apdu, openingTag(1))
		for _, p := range o.props {
			apdu = append(apdu, encodeContextEnumerated(2, uint64(p.id))...) // [2] property-identifier
			if p.isError {
				apdu = append(apdu, openingTag(5))
				cls, _ := EncodeApplication(AppTagEnumerated, uint64(p.errClass))
				code, _ := EncodeApplication(AppTagEnumerated, uint64(p.errCode))
				apdu = append(apdu, cls...)
				apdu = append(apdu, code...)
				apdu = append(apdu, closingTag(5))
				continue
			}
			appValue, _ := EncodeApplication(p.tag, p.val)
			apdu = append(apdu, openingTag(4))
			apdu = append(apdu, appValue...)
			apdu = append(apdu, closingTag(4))
		}
		apdu = append(apdu, closingTag(1))
	}
	return buildResponseFrame(apdu)
}

type rpmObject struct {
	oid   ObjectIdentifier
	props []rpmProp
}

type rpmProp struct {
	id       uint32
	tag      uint8
	val      interface{}
	errClass uint8
	errCode  uint8
	isError  bool
}

// TestParseStandardRpmFrame uses hand-written standard bytes (tags [0]/open-1/[2]/open-4/close-4/close-1),
// computed from ASHRAE 135 §20.2.15 — not the implementation's (now-fixed) dialect.
func TestParseStandardRpmFrame(t *testing.T) {
	// analog-input 0 present-value 21.5 (real)
	frame := []byte{
		0x81, 0x0a, 0x00, 0x19, 0x01, 0x00, 0x30, 0x01, 0x0e, // BVLC(0x19=25) + NPDU + ComplexACK RPM
		0x0c, 0x00, 0x00, 0x00, 0x00, // [0] OID analog-input 0
		0x1e,                   // open 1 (list-of-results)
		0x29, 0x55,             // [2] property-identifier 85 (present-value)
		0x4e,                   // open 4 (property-value)
		0x44, 0x41, 0xac, 0x00, 0x00, // real 21.5
		0x4f, // close 4
		0x1f, // close 1
	}
	// Cross-check the hand-written frame against the standard encoder.
	want := rpmAckFrame(1, rpmObject{
		oid:   ObjectIdentifier{Type: ObjectTypeAnalogInput, Instance: 0},
		props: []rpmProp{{id: PropertyPresentValue, tag: AppTagReal, val: float64(21.5)}},
	})
	if !bytes.Equal(frame, want) {
		t.Fatalf("hand-written frame % x != standard encoder % x", frame, want)
	}
	res, err := parseReadPropertyMultipleResponse(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].ObjectType != ObjectTypeAnalogInput || res[0].Instance != 0 {
		t.Errorf("result object = %+v, want analog-input 0", res[0])
	}
	if v := res[0].Values[PropertyPresentValue]; v != float64(21.5) {
		t.Errorf("present-value = %v, want 21.5", v)
	}
}

func TestParseStandardRpmFrameTwoObjects(t *testing.T) {
	// analog-input 0 present-value 21.5 + binary-input 1 present-value true
	frame := []byte{
		0x81, 0x0a, 0x00, 0x25, 0x01, 0x00, 0x30, 0x01, 0x0e, // BVLC(0x25=37) + NPDU + ComplexACK RPM
		0x0c, 0x00, 0x00, 0x00, 0x00, // [0] OID analog-input 0
		0x1e, 0x29, 0x55, 0x4e, 0x44, 0x41, 0xac, 0x00, 0x00, 0x4f, 0x1f,
		0x0c, 0x00, 0xc0, 0x00, 0x01, // [0] OID binary-input 1
		0x1e, 0x29, 0x55, 0x4e, 0x11, 0x4f, 0x1f,
	}
	want := rpmAckFrame(1,
		rpmObject{
			oid:   ObjectIdentifier{Type: ObjectTypeAnalogInput, Instance: 0},
			props: []rpmProp{{id: PropertyPresentValue, tag: AppTagReal, val: float64(21.5)}},
		},
		rpmObject{
			oid:   ObjectIdentifier{Type: ObjectTypeBinaryInput, Instance: 1},
			props: []rpmProp{{id: PropertyPresentValue, tag: AppTagBoolean, val: true}},
		},
	)
	if !bytes.Equal(frame, want) {
		t.Fatalf("hand-written frame % x != standard encoder % x", frame, want)
	}
	res, err := parseReadPropertyMultipleResponse(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2", len(res))
	}
	if res[0].Values[PropertyPresentValue] != float64(21.5) {
		t.Errorf("ai0 = %v, want 21.5", res[0].Values[PropertyPresentValue])
	}
	if res[1].ObjectType != ObjectTypeBinaryInput || res[1].Instance != 1 {
		t.Errorf("second object = %+v, want binary-input 1", res[1])
	}
	if res[1].Values[PropertyPresentValue] != true {
		t.Errorf("bi1 = %v, want true", res[1].Values[PropertyPresentValue])
	}
}

func TestClientReadMultipleViaMock(t *testing.T) {
	srv, err := NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()
	srv.SetRead(ObjectTypeAnalogInput, 0, PropertyPresentValue, AppTagReal, 21.5)
	srv.SetRead(ObjectTypeAnalogInput, 1, PropertyPresentValue, AppTagReal, 22.5)
	srv.SetRead(ObjectTypeBinaryInput, 2, PropertyPresentValue, AppTagBoolean, true)

	c, err := NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	specs := []AccessSpec{
		{ObjectType: ObjectTypeAnalogInput, Instance: 0, Properties: []uint32{PropertyPresentValue}},
		{ObjectType: ObjectTypeAnalogInput, Instance: 1, Properties: []uint32{PropertyPresentValue}},
		{ObjectType: ObjectTypeBinaryInput, Instance: 2, Properties: []uint32{PropertyPresentValue}},
	}
	res, err := c.ReadPropertyMultiple(specs)
	if err != nil {
		t.Fatalf("ReadPropertyMultiple error: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("got %d results, want 3", len(res))
	}
	want := map[string]interface{}{
		mockKey(ObjectTypeAnalogInput, 0, PropertyPresentValue): float64(21.5),
		mockKey(ObjectTypeAnalogInput, 1, PropertyPresentValue): float64(22.5),
		mockKey(ObjectTypeBinaryInput, 2, PropertyPresentValue): true,
	}
	got := map[string]interface{}{}
	for _, r := range res {
		got[mockKey(r.ObjectType, r.Instance, PropertyPresentValue)] = r.Values[PropertyPresentValue]
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestReadPropertyLargeId verifies that property identifiers above 255 (the proprietary range
// 512-4194303) round-trip through the wire. A single-byte property tag would silently truncate
// these; the encoder now emits a multi-byte context tag when needed.
func TestReadPropertyLargeId(t *testing.T) {
	srv, err := NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()
	const prop = uint32(3600) // proprietary property id, needs 2 bytes
	srv.SetRead(ObjectTypeAnalogInput, 0, prop, AppTagReal, 7.5)

	c, err := NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	v, err := c.ReadProperty(ObjectTypeAnalogInput, 0, prop)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if v != float64(7.5) {
		t.Errorf("got %v, want 7.5", v)
	}

	// Inspect the request payload to confirm a 2-byte property-identifier context tag was used.
	req, _ := readPropertyRequest(1, ObjectTypeAnalogInput, 0, prop)
	// APDU service request starts after BVLC(4)+NPDU(2)+APDU header(4) = offset 10.
	// Layout: [0x0C][oid 4B][ctx-tag-1 enumerated]. 3600 = 0x0E10 -> 2 bytes -> tag byte 0x99 (tag 1, class, lvt 1)... actually lvt 2.
	svc := req[10:]
	if svc[0] != 0x0C {
		t.Fatalf("expected ctx-tag 0 OID (0x0C), got %02x", svc[0])
	}
	propTag := svc[5]
	// context tag 1 with length 2: (1<<4)|0x08|0x02 = 0x1A
	if propTag != 0x1A {
		t.Fatalf("expected ctx-tag 1 length 2 (0x1A) for prop 3600, got %02x", propTag)
	}
	if binary.BigEndian.Uint16(svc[6:8]) != 3600 {
		t.Fatalf("encoded property id = %d, want 3600", binary.BigEndian.Uint16(svc[6:8]))
	}
}

// TestParseRpmWithArrayIndex verifies the parser skips the optional [3] property-array-index
// when a device includes it (ASHRAE 135 §20.2.15 list-of-results sequence).
func TestParseRpmWithArrayIndex(t *testing.T) {
	// Build a frame with one object, one result that carries a [3] array index before open-4.
	apdu := []byte{pduComplexAck << 4, 1, svcReadPropMultiple}
	apdu = append(apdu, 0x0C)
	apdu = append(apdu, oidBytes(ObjectTypeAnalogInput, 0)...)
	apdu = append(apdu, openingTag(1))
	apdu = append(apdu, encodeContextEnumerated(2, uint64(PropertyPresentValue))...) // [2] property id
	apdu = append(apdu, encodeContextEnumerated(3, 1)...)                            // [3] array index = 1
	appValue, _ := EncodeApplication(AppTagReal, float64(9.25))
	apdu = append(apdu, openingTag(4))
	apdu = append(apdu, appValue...)
	apdu = append(apdu, closingTag(4))
	apdu = append(apdu, closingTag(1))
	frame := buildResponseFrame(apdu)

	res, err := parseReadPropertyMultipleResponse(frame)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if v := res[0].Values[PropertyPresentValue]; v != float64(9.25) {
		t.Errorf("present-value = %v, want 9.25", v)
	}
}
