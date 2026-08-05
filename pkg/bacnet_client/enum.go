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

// Package bacnetclient implements a self-contained BACnet/IP acquisition client
// (read/write object properties) over UDP. Pure standard library implementation,
// synchronous request/response pairing. Only the acquisition-relevant BACnet/IP
// subset is implemented: Original-Unicast-NPDU framing, ReadProperty,
// WriteProperty and the common application data types.
package bacnetclient

import (
	"fmt"
	"strconv"
	"strings"
)

// BACnet object types (ASHRAE 135 bacenum.h), acquisition-relevant subset.
const (
	ObjectTypeAnalogInput      uint16 = 0
	ObjectTypeAnalogOutput     uint16 = 1
	ObjectTypeAnalogValue      uint16 = 2
	ObjectTypeBinaryInput      uint16 = 3
	ObjectTypeBinaryOutput     uint16 = 4
	ObjectTypeBinaryValue      uint16 = 5
	ObjectTypeDevice           uint16 = 8
	ObjectTypeMultiStateInput  uint16 = 13
	ObjectTypeMultiStateOutput uint16 = 14
	ObjectTypeMultiStateValue  uint16 = 19
)

// BACnet property identifiers (ASHRAE 135 bacenum.h), acquisition-relevant subset.
// PropertyIdentifier is a uint32 because BACnet defines standard properties up to ~520
// and reserves the proprietary range 512-4194303, which does not fit in a byte.
const (
	PropertyObjectIdentifier  uint32 = 75
	PropertyObjectList        uint32 = 76
	PropertyObjectName        uint32 = 77
	PropertyObjectType        uint32 = 79
	PropertyDescription       uint32 = 28
	PropertyPresentValue      uint32 = 85
	PropertyPriorityArray     uint32 = 87
	PropertyRelinquishDefault uint32 = 104
	PropertyUnits             uint32 = 117
)

// ObjectIdentifier is a BACnet object identifier: 10-bit type + 22-bit instance.
type ObjectIdentifier struct {
	Type     uint16
	Instance uint32
}

// objectTypes maps object-type tokens (kebab / camel / short) to type code.
var objectTypes = map[string]uint16{
	"analog-input": ObjectTypeAnalogInput, "analoginput": ObjectTypeAnalogInput, "ai": ObjectTypeAnalogInput,
	"analog-output": ObjectTypeAnalogOutput, "analogoutput": ObjectTypeAnalogOutput, "ao": ObjectTypeAnalogOutput,
	"analog-value": ObjectTypeAnalogValue, "analogvalue": ObjectTypeAnalogValue, "av": ObjectTypeAnalogValue,
	"binary-input": ObjectTypeBinaryInput, "binaryinput": ObjectTypeBinaryInput, "bi": ObjectTypeBinaryInput,
	"binary-output": ObjectTypeBinaryOutput, "binaryoutput": ObjectTypeBinaryOutput, "bo": ObjectTypeBinaryOutput,
	"binary-value": ObjectTypeBinaryValue, "binaryvalue": ObjectTypeBinaryValue, "bv": ObjectTypeBinaryValue,
	"device": ObjectTypeDevice, "dev": ObjectTypeDevice,
	"multi-state-input": ObjectTypeMultiStateInput, "multistate-input": ObjectTypeMultiStateInput, "multistateinput": ObjectTypeMultiStateInput, "msi": ObjectTypeMultiStateInput,
	"multi-state-output": ObjectTypeMultiStateOutput, "multistate-output": ObjectTypeMultiStateOutput, "multistateoutput": ObjectTypeMultiStateOutput, "mso": ObjectTypeMultiStateOutput,
	"multi-state-value": ObjectTypeMultiStateValue, "multistate-value": ObjectTypeMultiStateValue, "multistatevalue": ObjectTypeMultiStateValue, "msv": ObjectTypeMultiStateValue,
}

// properties maps property tokens to property identifier.
var properties = map[string]uint32{
	"present-value": PropertyPresentValue, "presentvalue": PropertyPresentValue, "pv": PropertyPresentValue,
	"description": PropertyDescription, "desc": PropertyDescription,
	"object-name": PropertyObjectName, "objectname": PropertyObjectName, "name": PropertyObjectName,
	"object-identifier": PropertyObjectIdentifier, "objectidentifier": PropertyObjectIdentifier,
	"object-type": PropertyObjectType, "objecttype": PropertyObjectType,
	"units": PropertyUnits, "unit": PropertyUnits,
	"priority-array": PropertyPriorityArray, "priorityarray": PropertyPriorityArray,
	"relinquish-default": PropertyRelinquishDefault, "relinquishdefault": PropertyRelinquishDefault,
	"object-list": PropertyObjectList, "objectlist": PropertyObjectList,
}

// ParseObjectType resolves an object-type token (name / alias / decimal) to a type code.
func ParseObjectType(s string) (uint16, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if v, ok := objectTypes[s]; ok {
		return v, nil
	}
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n), nil
	}
	return 0, fmt.Errorf("bacnet: unknown object type %q", s)
}

// ParseProperty resolves a property token (name / alias / decimal) to a property identifier.
// The identifier may exceed 255 (proprietary range is 512-4194303), so it is returned as uint32.
func ParseProperty(s string) (uint32, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if v, ok := properties[s]; ok {
		return v, nil
	}
	// BACnet PropertyIdentifier fits in 22 bits (0..4194303).
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), nil
	}
	return 0, fmt.Errorf("bacnet: unknown property %q", s)
}
