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
	"net"
	"sync"
)

// MockEntry pairs a BACnet application data tag with its Go value for mock responses.
type MockEntry struct {
	Tag   uint8
	Value interface{}
}

// MockServer is an in-process BACnet/IP server for tests. It answers ReadProperty with configured
// values and acknowledges WriteProperty, capturing the written values.
type MockServer struct {
	conn   *net.UDPConn
	mu     sync.Mutex
	values map[string]MockEntry // key "type:instance:property"
	errOn  map[string]bool
	writes map[string]interface{}
	rpmUnsupported bool // respond to ReadPropertyMultiple with an Error (drives fallback tests)
}

// NewMockServer starts a mock BACnet/IP server listening on 127.0.0.1 with an ephemeral port.
func NewMockServer() (*MockServer, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	s := &MockServer{
		conn:   conn,
		values: make(map[string]MockEntry),
		errOn:  make(map[string]bool),
		writes: make(map[string]interface{}),
	}
	go s.serve()
	return s, nil
}

// Addr returns the "127.0.0.1:port" address clients should connect to.
func (s *MockServer) Addr() string { return s.conn.LocalAddr().String() }

// SetRead configures the value returned for a ReadProperty on the given object/property.
func (s *MockServer) SetRead(objType uint16, instance uint32, property uint32, tag uint8, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[mockKey(objType, instance, property)] = MockEntry{Tag: tag, Value: value}
}

// SetError makes ReadProperty on the given object/property return a BACnet Error response.
func (s *MockServer) SetError(objType uint16, instance uint32, property uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errOn[mockKey(objType, instance, property)] = true
}

// SetRpmUnsupported makes the server reject ReadPropertyMultiple with an Error response,
// so clients must fall back to per-point ReadProperty.
func (s *MockServer) SetRpmUnsupported() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rpmUnsupported = true
}

// Writes returns a copy of the values captured from WriteProperty requests (key "type:instance:property").
func (s *MockServer) Writes() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]interface{}, len(s.writes))
	for k, v := range s.writes {
		out[k] = v
	}
	return out
}

// Close stops the mock server.
func (s *MockServer) Close() error { return s.conn.Close() }

func mockKey(objType uint16, instance uint32, property uint32) string {
	return fmt.Sprintf("%d:%d:%d", objType, instance, property)
}

func (s *MockServer) serve() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.handle(buf[:n], addr)
	}
}

func (s *MockServer) handle(req []byte, addr *net.UDPAddr) {
	info, err := parseRequest(req)
	if err != nil {
		return
	}
	switch info.service {
	case svcReadProperty:
		oid, n, err := parseContextObjectIdentifier(info.serviceRequest, 0)
		if err != nil {
			return
		}
		prop, _, err := parseContextEnumerated(info.serviceRequest[n:], 1)
		if err != nil {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		k := mockKey(oid.Type, oid.Instance, prop)
		if s.errOn[k] {
			_, _ = s.conn.WriteToUDP(buildErrorACK(info.invokeID), addr)
			return
		}
		entry, ok := s.values[k]
		if !ok {
			_, _ = s.conn.WriteToUDP(buildErrorACK(info.invokeID), addr)
			return
		}
		_, _ = s.conn.WriteToUDP(buildComplexACK(info.invokeID, oid, prop, entry), addr)
	case svcWriteProperty:
		oid, n, err := parseContextObjectIdentifier(info.serviceRequest, 0)
		if err != nil {
			return
		}
		prop, m, err := parseContextEnumerated(info.serviceRequest[n:], 1)
		if err != nil {
			return
		}
		v, _ := scanValue(info.serviceRequest[n+m:])
		s.mu.Lock()
		s.writes[mockKey(oid.Type, oid.Instance, prop)] = v
		s.mu.Unlock()
		_, _ = s.conn.WriteToUDP(buildSimpleACK(info.invokeID), addr)
	case svcReadPropMultiple:
		s.mu.Lock()
		unsupported := s.rpmUnsupported
		s.mu.Unlock()
		if unsupported {
			apdu := []byte{pduError << 4, info.invokeID, svcReadPropMultiple}
			cls, _ := EncodeApplication(AppTagEnumerated, uint64(5)) // errorClassServices
			code, _ := EncodeApplication(AppTagEnumerated, uint64(4)) // errorCodeUnrecognizedService
			apdu = append(apdu, cls...)
			apdu = append(apdu, code...)
			_, _ = s.conn.WriteToUDP(buildResponseFrame(apdu), addr)
			return
		}
		specs, err := parseRpmRequest(info.serviceRequest)
		if err != nil {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		apdu := []byte{pduComplexAck << 4, info.invokeID, svcReadPropMultiple}
		for _, sp := range specs {
			apdu = append(apdu, 0x0C) // context tag 0, length 4 — object-identifier
			apdu = append(apdu, oidBytes(sp.ObjectType, sp.Instance)...)
			apdu = append(apdu, openingTag(1)) // list-of-results
			for _, prop := range sp.Properties {
				apdu = append(apdu, encodeContextEnumerated(2, uint64(prop))...) // [2] property-identifier
				k := mockKey(sp.ObjectType, sp.Instance, prop)
				entry, ok := s.values[k]
				if !ok || s.errOn[k] {
					apdu = append(apdu, openingTag(5)) // property-access-error
					cls, _ := EncodeApplication(AppTagEnumerated, uint64(1))
					code, _ := EncodeApplication(AppTagEnumerated, uint64(31))
					apdu = append(apdu, cls...)
					apdu = append(apdu, code...)
					apdu = append(apdu, closingTag(5))
					continue
				}
				appValue, _ := EncodeApplication(entry.Tag, entry.Value)
				apdu = append(apdu, openingTag(4)) // property-value
				apdu = append(apdu, appValue...)
				apdu = append(apdu, closingTag(4))
			}
			apdu = append(apdu, closingTag(1))
		}
		_, _ = s.conn.WriteToUDP(buildResponseFrame(apdu), addr)
	}
}

// parseRpmRequest parses a ReadPropertyMultiple request service-request into access specs.
func parseRpmRequest(b []byte) ([]AccessSpec, error) {
	specs := make([]AccessSpec, 0)
	off := 0
	for off < len(b) {
		oid, n, err := parseContextObjectIdentifier(b[off:], 0)
		if err != nil {
			return specs, err
		}
		off += n
		if off >= len(b) || b[off] != openingTag(1) {
			return specs, fmt.Errorf("bacnet rpm request: expected opening tag 1")
		}
		off++
		sp := AccessSpec{ObjectType: oid.Type, Instance: oid.Instance}
		for off < len(b) && b[off] != closingTag(1) {
			prop, pn, err := parseContextEnumerated(b[off:], 0)
			if err != nil {
				return specs, err
			}
			off += pn
			sp.Properties = append(sp.Properties, prop)
		}
		if off < len(b) && b[off] == closingTag(1) {
			off++
		}
		specs = append(specs, sp)
	}
	return specs, nil
}

func oidBytes(t uint16, inst uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(t)<<22|inst)
	return b
}

func buildComplexACK(invokeID uint8, oid ObjectIdentifier, prop uint32, entry MockEntry) []byte {
	appValue, _ := EncodeApplication(entry.Tag, entry.Value)
	payload := []byte{0x0C}
	payload = append(payload, oidBytes(oid.Type, oid.Instance)...)
	payload = append(payload, encodeContextEnumerated(1, uint64(prop))...)
	payload = append(payload, openingTag(3))
	payload = append(payload, appValue...)
	payload = append(payload, closingTag(3))
	apdu := []byte{pduComplexAck << 4, invokeID, svcReadProperty}
	apdu = append(apdu, payload...)
	return buildResponseFrame(apdu)
}

func buildSimpleACK(invokeID uint8) []byte {
	return buildResponseFrame([]byte{pduSimpleAck << 4, invokeID, svcWriteProperty})
}

func buildErrorACK(invokeID uint8) []byte {
	cls, _ := EncodeApplication(AppTagEnumerated, uint64(1))
	code, _ := EncodeApplication(AppTagEnumerated, uint64(31))
	apdu := []byte{pduError << 4, invokeID, svcReadProperty}
	apdu = append(apdu, cls...)
	apdu = append(apdu, code...)
	return buildResponseFrame(apdu)
}
