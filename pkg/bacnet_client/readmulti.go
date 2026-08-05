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

import "fmt"

const svcReadPropMultiple uint8 = 0x0e

// AccessSpec is one entry of a ReadPropertyMultiple request: an object and the properties to read.
type AccessSpec struct {
	ObjectType uint16
	Instance   uint32
	Properties []uint32
}

// ReadAccessResult is one object's results from a ReadPropertyMultiple response.
type ReadAccessResult struct {
	ObjectType uint16
	Instance   uint32
	Values     map[uint32]interface{} // property id -> decoded value (first value)
	Errors     map[uint32]error       // property id -> error (device returned a read-result error)
}

// readPropertyMultipleRequest builds a ReadPropertyMultiple request frame.
// Each access specification is: context-tag-0 object-identifier + opening-tag-1 +
// (context-tag-0 property-identifier)* + closing-tag-1.
func readPropertyMultipleRequest(invokeID uint8, specs []AccessSpec) ([]byte, error) {
	payload := make([]byte, 0, 16*len(specs))
	for _, sp := range specs {
		payload = append(payload, 0x0C) // context tag 0, length 4
		payload = append(payload, oidBytes(sp.ObjectType, sp.Instance)...)
		payload = append(payload, openingTag(1)) // listOfPropertyReferences
		for _, prop := range sp.Properties {
			payload = append(payload, encodeContextEnumerated(0, uint64(prop))...) // [0] property-identifier
		}
		payload = append(payload, closingTag(1))
	}
	return buildFrame(confirmedReqAPDU(invokeID, svcReadPropMultiple, payload)), nil
}

// parseReadPropertyMultipleResponse decodes a ReadPropertyMultiple ComplexACK into per-object results.
func parseReadPropertyMultipleResponse(frame []byte) ([]ReadAccessResult, error) {
	info, err := parseResponse(frame)
	if err != nil {
		return nil, err
	}
	switch info.pduType {
	case pduComplexAck:
		return parseReadAccessResults(info.serviceRequest)
	case pduError:
		return nil, parseServiceError(info.serviceRequest)
	case pduReject, pduAbort:
		return nil, fmt.Errorf("bacnet: read-multiple rejected/aborted (type %d)", info.pduType)
	}
	return nil, errUnexpected
}

// parseReadAccessResults walks the ListOfReadAccessResults (ASHRAE 135 §20.2.15):
//
//	ReadAccessResult ::= SEQUENCE {
//	    object-identifier  [0] BACnetObjectIdentifier,
//	    list-of-results    [1] SEQUENCE OF SEQUENCE {
//	        property-identifier  [2] BACnetPropertyIdentifier,
//	        property-array-index [3] Unsigned OPTIONAL,
//	        read-result CHOICE {
//	            property-value        [4] ABSTRACT-SYNTAX.&Type,
//	            property-access-error [5] Error
//	        }
//	    }
//	}
func parseReadAccessResults(b []byte) ([]ReadAccessResult, error) {
	results := make([]ReadAccessResult, 0)
	off := 0
	for off < len(b) {
		oid, n, err := parseContextObjectIdentifier(b[off:], 0)
		if err != nil {
			return results, err
		}
		off += n
		if off >= len(b) || b[off] != openingTag(1) {
			return results, fmt.Errorf("bacnet rpm: expected opening tag 1")
		}
		off++ // open 1
		res := ReadAccessResult{ObjectType: oid.Type, Instance: oid.Instance, Values: map[uint32]interface{}{}, Errors: map[uint32]error{}}
		for off < len(b) && b[off] != closingTag(1) {
			prop, pn, err := parseContextEnumerated(b[off:], 2)
			if err != nil {
				return results, err
			}
			off += pn
			// Optional property-array-index, context tag 3.
			if off < len(b) && isContextTag(b[off], 3) {
				_, an, aerr := parseContextUint(b[off:], 3)
				if aerr != nil {
					return results, aerr
				}
				off += an
			}
			if off >= len(b) {
				return results, fmt.Errorf("bacnet rpm: truncated result for property %d", prop)
			}
			switch b[off] {
			case openingTag(4): // property-value
				off++
				val, consumed, derr := decodeAppUntilClose(b[off:], 4)
				off += consumed
				if derr != nil {
					res.Errors[prop] = derr
				} else {
					res.Values[prop] = val
				}
			case openingTag(5): // property-access-error: open5, class(enum), code(enum), close5
				off++
				if cls, c, e1 := decodeFirstEnumerated(b[off:]); e1 == nil {
					off += c
					if code, c2, e2 := decodeFirstEnumerated(b[off:]); e2 == nil {
						off += c2
						res.Errors[prop] = ServiceError{Class: cls, Code: code}
					}
				}
				off = skipToClosing(b, off, 5)
			default:
				return results, fmt.Errorf("bacnet rpm: unexpected tag %x for property %d", b[off], prop)
			}
		}
		if off < len(b) && b[off] == closingTag(1) {
			off++ // close 1
		}
		results = append(results, res)
	}
	return results, nil
}

// decodeAppUntilClose decodes the first application value inside an opening tag, consuming bytes
// through (and including) closingTag(closeTagNum). Additional values (arrays) are skipped.
func decodeAppUntilClose(b []byte, closeTagNum uint8) (interface{}, int, error) {
	off := 0
	var first interface{}
	for off < len(b) {
		if b[off] == closingTag(closeTagNum) {
			if first == nil {
				return nil, off + 1, fmt.Errorf("bacnet: empty value")
			}
			return first, off + 1, nil
		}
		v, consumed, err := DecodeApplication(b[off:])
		if err != nil {
			return first, off, err
		}
		if first == nil {
			first = v
		}
		off += consumed
	}
	return first, off, fmt.Errorf("bacnet: missing closing tag %d", closeTagNum)
}

// skipToClosing advances off past the next closingTag(tagNum) (best-effort error recovery).
func skipToClosing(b []byte, off int, tagNum uint8) int {
	for off < len(b) {
		if b[off] == closingTag(tagNum) {
			return off + 1
		}
		off++
	}
	return off
}
