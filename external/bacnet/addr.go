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

package bacnet

import (
	"fmt"
	"strconv"
	"strings"

	bacnetclient "github.com/rulego/rulego-components-iot/pkg/bacnet_client"
)

// PointAddr is a parsed BACnet point address.
type PointAddr struct {
	ObjectType uint16
	Instance   uint32
	Property   uint32
}

// ParsePointAddr parses "<objectType>:<instance>[:<property>]".
// The property part is optional and defaults to present-value. Object type and property tokens
// accept standard names, short aliases (ai/ao/.../pv) or decimal numbers.
func ParsePointAddr(addr string) (PointAddr, error) {
	addr = strings.TrimSpace(addr)
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return PointAddr{}, fmt.Errorf("bacnet addr %q: want <objectType>:<instance>[:<property>]", addr)
	}
	objType, err := bacnetclient.ParseObjectType(parts[0])
	if err != nil {
		return PointAddr{}, err
	}
	instance, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return PointAddr{}, fmt.Errorf("bacnet addr %q: invalid instance: %w", addr, err)
	}
	property := bacnetclient.PropertyPresentValue
	if len(parts) >= 3 && parts[2] != "" {
		property, err = bacnetclient.ParseProperty(parts[2])
		if err != nil {
			return PointAddr{}, err
		}
	}
	return PointAddr{ObjectType: objType, Instance: uint32(instance), Property: property}, nil
}
