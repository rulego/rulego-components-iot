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
	"reflect"
	"testing"
	"time"
)

// TestParseStandardFrames feeds hand-crafted BACnet/IP ReadProperty ComplexACK frames
// (byte values computed from ASHRAE 135, not from this implementation) to the response parser.
// This proves the client decodes real BACnet responses, independent of the mock server.
func TestParseStandardFrames(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		want  interface{}
	}{
		{
			name:  "analog-input 0 present-value 21.5",
			frame: []byte{0x81, 0x0a, 0x00, 0x17, 0x01, 0x00, 0x30, 0x01, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x19, 0x55, 0x3e, 0x44, 0x41, 0xac, 0x00, 0x00, 0x3f},
			want:  float64(21.5),
		},
		{
			name:  "binary-input 0 present-value true",
			frame: []byte{0x81, 0x0a, 0x00, 0x13, 0x01, 0x00, 0x30, 0x01, 0x0c, 0x0c, 0x00, 0xc0, 0x00, 0x00, 0x19, 0x55, 0x3e, 0x11, 0x3f},
			want:  true,
		},
		{
			name:  "multi-state-input 2 present-value 3",
			frame: []byte{0x81, 0x0a, 0x00, 0x14, 0x01, 0x00, 0x30, 0x01, 0x0c, 0x0c, 0x03, 0x40, 0x00, 0x02, 0x19, 0x55, 0x3e, 0x91, 0x03, 0x3f},
			want:  uint64(3),
		},
		{
			name:  "analog-input 0 object-name OK",
			frame: []byte{0x81, 0x0a, 0x00, 0x16, 0x01, 0x00, 0x30, 0x01, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x19, 0x4d, 0x3e, 0x73, 0x04, 0x4f, 0x4b, 0x3f},
			want:  "OK",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseReadPropertyResponse(c.frame)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v (%T), want %v (%T)", got, got, c.want, c.want)
			}
		})
	}
}

func TestParseErrorResponse(t *testing.T) {
	// Error APDU: type 0x40, invokeID 1, service 0x0c, error-class=1(enum), error-code=31(enum).
	frame := []byte{0x81, 0x0a, 0x00, 0x0e, 0x01, 0x00, 0x40, 0x01, 0x0c, 0x91, 0x01, 0x91, 0x1f}
	_, err := parseReadPropertyResponse(frame)
	se, ok := err.(ServiceError)
	if !ok {
		t.Fatalf("expected ServiceError, got %v", err)
	}
	if se.Class != 1 || se.Code != 31 {
		t.Errorf("error class=%d code=%d, want class=1 code=31", se.Class, se.Code)
	}
}

func TestClientReadViaMock(t *testing.T) {
	srv, err := NewMockServer()
	if err != nil {
		t.Fatalf("mock server: %v", err)
	}
	defer srv.Close()
	srv.SetRead(ObjectTypeAnalogInput, 0, PropertyPresentValue, AppTagReal, float64(21.5))
	srv.SetRead(ObjectTypeBinaryInput, 1, PropertyPresentValue, AppTagBoolean, true)
	srv.SetRead(ObjectTypeMultiStateInput, 2, PropertyPresentValue, AppTagEnumerated, uint64(3))
	srv.SetRead(ObjectTypeAnalogInput, 0, PropertyObjectName, AppTagCharacterString, "roof-temp")
	srv.SetError(ObjectTypeAnalogInput, 9, PropertyPresentValue)

	c, err := NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	checks := []struct {
		name     string
		objType  uint16
		instance uint32
		property uint32
		want     interface{}
		wantErr  bool
	}{
		{"analog real", ObjectTypeAnalogInput, 0, PropertyPresentValue, float64(21.5), false},
		{"binary bool", ObjectTypeBinaryInput, 1, PropertyPresentValue, true, false},
		{"multistate enum", ObjectTypeMultiStateInput, 2, PropertyPresentValue, uint64(3), false},
		{"string name", ObjectTypeAnalogInput, 0, PropertyObjectName, "roof-temp", false},
		{"error", ObjectTypeAnalogInput, 9, PropertyPresentValue, nil, true},
	}
	for _, ck := range checks {
		t.Run(ck.name, func(t *testing.T) {
			got, err := c.ReadProperty(ck.objType, ck.instance, ck.property)
			if ck.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if !reflect.DeepEqual(got, ck.want) {
				t.Errorf("got %v (%T), want %v (%T)", got, got, ck.want, ck.want)
			}
		})
	}
}

func TestClientWriteViaMock(t *testing.T) {
	srv, err := NewMockServer()
	if err != nil {
		t.Fatalf("mock server: %v", err)
	}
	defer srv.Close()

	c, err := NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if err := c.WriteProperty(ObjectTypeAnalogOutput, 0, PropertyPresentValue, AppTagReal, float64(18.5), 8); err != nil {
		t.Fatalf("write analog: %v", err)
	}
	if err := c.WriteProperty(ObjectTypeBinaryOutput, 1, PropertyPresentValue, AppTagBoolean, true, 0); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	if err := c.WriteProperty(ObjectTypeMultiStateValue, 2, PropertyPresentValue, AppTagEnumerated, uint64(2), 0); err != nil {
		t.Fatalf("write multistate: %v", err)
	}

	writes := srv.Writes()
	if got := writes["1:0:85"]; got != float64(18.5) {
		t.Errorf("analog write recorded %v, want 18.5", got)
	}
	if got := writes["4:1:85"]; got != true {
		t.Errorf("binary write recorded %v, want true", got)
	}
	if got := writes["19:2:85"]; got != uint64(2) {
		t.Errorf("multistate write recorded %v, want 2", got)
	}
}
