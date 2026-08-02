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

package iot_points

// Driver acquisition driver interface. Driver holds protocol connection (lifecycle managed by SharedNode),
// responsible for parsing Point.Addr to protocol addressing and reading/writing devices.
type Driver interface {
	// ReadPoints reads points, returns acquisition result for each point
	ReadPoints(points []Point) ([]Data, error)
	// WritePoints writes points (Value field is write value)
	WritePoints(points []Point) error
}
