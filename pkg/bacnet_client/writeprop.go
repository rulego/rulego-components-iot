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
)

// ServiceError carries a BACnet error-class / error-code pair.
type ServiceError struct {
	Class uint8
	Code  uint8
}

func (e ServiceError) Error() string {
	return fmt.Sprintf("bacnet error: class=%d code=%d", e.Class, e.Code)
}

// parseServiceError decodes an Error APDU service-request: two enumerated application tags (class, code).
func parseServiceError(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("bacnet: truncated error response")
	}
	cls, n, err := decodeFirstEnumerated(b)
	if err != nil {
		return err
	}
	code, _, err := decodeFirstEnumerated(b[n:])
	if err != nil {
		return err
	}
	return ServiceError{Class: cls, Code: code}
}

func decodeFirstEnumerated(b []byte) (uint8, int, error) {
	v, consumed, err := DecodeApplication(b)
	if err != nil {
		return 0, 0, err
	}
	n, ok := v.(uint64)
	if !ok {
		return 0, 0, fmt.Errorf("bacnet: expected enumerated value, got %T", v)
	}
	return uint8(n), consumed, nil
}

// writePropertyRequest builds a BACnet/IP WriteProperty request frame.
// valueTag selects the BACnet application data type; priority 0 omits the priority field.
func writePropertyRequest(invokeID uint8, objType uint16, instance uint32, property uint32, valueTag uint8, value interface{}, priority uint8) ([]byte, error) {
	appValue, err := EncodeApplication(valueTag, value)
	if err != nil {
		return nil, err
	}
	oid := make([]byte, 4)
	binary.BigEndian.PutUint32(oid, uint32(objType)<<22|instance)

	payload := make([]byte, 0, 12+len(appValue))
	payload = append(payload, 0x0C) // context tag 0
	payload = append(payload, oid...)
	payload = append(payload, encodeContextEnumerated(1, uint64(property))...) // [1] property-identifier
	payload = append(payload, openingTag(3))                                    // opening tag 3 (property value)
	payload = append(payload, appValue...)
	payload = append(payload, closingTag(3)) // closing tag 3
	if priority != 0 {
		payload = append(payload, 0x49, priority) // context tag 4 (priority)
	}
	return buildFrame(confirmedReqAPDU(invokeID, svcWriteProperty, payload)), nil
}

// parseWritePropertyResponse returns nil on SimpleACK, or a ServiceError on Error.
func parseWritePropertyResponse(frame []byte) error {
	info, err := parseResponse(frame)
	if err != nil {
		return err
	}
	switch info.pduType {
	case pduSimpleAck:
		return nil
	case pduError:
		return parseServiceError(info.serviceRequest)
	case pduReject, pduAbort:
		return fmt.Errorf("bacnet: write rejected/aborted (type %d)", info.pduType)
	}
	return errUnexpected
}
