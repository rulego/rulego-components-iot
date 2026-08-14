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

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/rulego/rulego/utils/cast"
)

// Collection node shared constants
const (
	// DefaultMaxRetries max retries after connection-level failure
	DefaultMaxRetries = 3
	// ReconnectDelay wait before reconnection
	ReconnectDelay = 200 * time.Millisecond
	// DefaultTimeoutSec default request timeout (seconds)
	DefaultTimeoutSec = 5
)

// BackoffFor returns the reconnect backoff for the given (0-based) attempt.
func BackoffFor(attempt int) time.Duration {
	switch attempt {
	case 0:
		return 200 * time.Millisecond
	case 1:
		return 500 * time.Millisecond
	case 2:
		return time.Second
	default:
		return 2 * time.Second
	}
}

// IsTimeoutErr reports whether err is a timeout-class failure: the peer did not
// answer before the deadline. Callers use it to skip per-point fallbacks and
// reconnect retries that would each burn another full timeout window.
func IsTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Protocol libraries report timeouts as flat strings with no %w chain.
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded")
}

// Common data type enumeration (protocol-independent). Each driver maps to protocol native types.
const (
	TypeBool    = "BOOL"
	TypeInt16   = "INT16"
	TypeUint16  = "UINT16"
	TypeInt32   = "INT32"
	TypeUint32  = "UINT32"
	TypeInt64   = "INT64"
	TypeUint64  = "UINT64"
	TypeFloat32 = "FLOAT32"
	TypeFloat64 = "FLOAT64"
	TypeString  = "STRING"
)

// Point unified acquisition point (configuration layer, fields support ${msg.xx}/${metadata.xx} templates).
// Addr is protocol addressing string, parsed by each driver (e.g. s7 "DB1.DBD0"/"M0.1", modbus Modicon "40001",
// opcua NodeID "ns=2;s=Temperature", snmp OID "1.3.6.1...", mc "D100", fins "CIO100"/"D100.5").
type Point struct {
	Name   string  `json:"name"`             // Point name, used as Data.Name in output (for downstream access)
	Addr   string  `json:"addr"`             // Protocol addressing string, parsed by each driver (see package comment for format)
	Type   string  `json:"type"`             // Data type, values from TypeXxx enumeration; empty uses protocol default type
	Scale  float64 `json:"scale,omitempty"`  // Engineering scaling factor, 0 means no scaling (see ApplyScale)
	Offset float64 `json:"offset,omitempty"` // Engineering offset, 0 means no offset
	Endian string  `json:"endian,omitempty"` // Byte order ABCD/CDAB/BADC/DCBA, only effective for multi-register types
	Value  string  `json:"value,omitempty"`  // Write value (string form, driver parses by Type)
}

// Data acquisition result (single point). Read node outputs []Data, single point failure marked with Error rather than batch failure.
type Data struct {
	Name      string      `json:"name"`                // Point name, corresponds to Point.Name
	Value     interface{} `json:"value"`               // Read value (protocol native type); empty for bad points
	Timestamp int64       `json:"timestamp,omitempty"` // Acquisition timestamp (ns), 0 means protocol not provided
	Error     string      `json:"error,omitempty"`     // Single point error message, empty means success
}

// ApplyScale engineering conversion: eng = raw*scale + offset.
// When Scale/Offset are both 0, returns raw as-is; note when scale=0 and offset≠0, result is offset (raw discarded,
// if only translation needed explicitly configure scale=1).
func ApplyScale(raw float64, p Point) float64 {
	if p.Scale == 0 && p.Offset == 0 {
		return raw
	}
	return raw*p.Scale + p.Offset
}

// ScaleValue applies point engineering conversion to numeric values, result is float64.
// When Scale/Offset are both 0, or value is non-numeric type (bool, etc.), returns as-is.
func ScaleValue(v interface{}, p Point) interface{} {
	if p.Scale == 0 && p.Offset == 0 {
		return v
	}
	if f, err := cast.ToFloat64E(v); err == nil {
		return ApplyScale(f, p)
	}
	return v
}

// NewData assembles single point acquisition result: qualityBad marks bad point; otherwise applies point engineering conversion to numeric values.
func NewData(name string, value interface{}, qualityBad bool, timestamp time.Time, p Point) Data {
	if qualityBad {
		return Data{Name: name, Error: "read failed (quality=bad)"}
	}
	return Data{Name: name, Value: ScaleValue(value, p), Timestamp: timestamp.UnixNano()}
}

// RenderPoint renders Point string field templates (Name/Addr/Type/Endian/Value), Scale/Offset pass through.
// Called by node layer with env constructed from ctx+msg, driver receives rendered Point (no ${}).
func RenderPoint(p Point, env map[string]interface{}) Point {
	return Point{
		Name:   RenderTemplate(p.Name, env),
		Addr:   RenderTemplate(p.Addr, env),
		Type:   RenderTemplate(p.Type, env),
		Scale:  p.Scale,
		Offset: p.Offset,
		Endian: RenderTemplate(p.Endian, env),
		Value:  RenderTemplate(p.Value, env),
	}
}
