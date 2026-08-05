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

// readPropertyRequest builds a BACnet/IP ReadProperty request frame.
// Service-request payload: context-tag-0 object-identifier + context-tag-1 property-identifier.
func readPropertyRequest(invokeID uint8, objType uint16, instance uint32, property uint32) ([]byte, error) {
	oid := make([]byte, 4)
	binary.BigEndian.PutUint32(oid, uint32(objType)<<22|instance)
	payload := make([]byte, 0, 8)
	payload = append(payload, 0x0C) // context tag 0, length 4
	payload = append(payload, oid...)
	payload = append(payload, encodeContextEnumerated(1, uint64(property))...) // [1] property-identifier
	return buildFrame(confirmedReqAPDU(invokeID, svcReadProperty, payload)), nil
}

// parseReadPropertyResponse decodes a ReadProperty ComplexACK into the property value.
// Error / Reject / Abort responses are surfaced as Go errors.
func parseReadPropertyResponse(frame []byte) (interface{}, error) {
	info, err := parseResponse(frame)
	if err != nil {
		return nil, err
	}
	switch info.pduType {
	case pduComplexAck:
		return scanValue(info.serviceRequest)
	case pduError:
		return nil, parseServiceError(info.serviceRequest)
	case pduReject, pduAbort:
		return nil, fmt.Errorf("bacnet: read rejected/aborted (type %d)", info.pduType)
	}
	return nil, errUnexpected
}
