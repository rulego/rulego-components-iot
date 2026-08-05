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

package opcuaClient

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/stretchr/testify/assert"
)

// TestToPointsData: OK points filled with Value+Timestamp, bad points filled with Error; Name priority points.Name → DisplayName → points.Addr.
func TestToPointsData(t *testing.T) {
	points := []iot_points.Point{
		{Name: "Temperature", Addr: "ns=2;s=A"},
		{Addr: "ns=2;s=B"},
		{Addr: "ns=2;s=C"},
	}
	data := []Data{
		{NodeId: "ns=2;s=A", DisplayName: "Temp"},
		{NodeId: "ns=2;s=B", DisplayName: "Pressure"},
		{NodeId: "ns=2;s=C"},
	}
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	v, _ := ua.NewVariant(23.5)
	resp := &ua.ReadResponse{
		Results: []*ua.DataValue{
			{Status: ua.StatusOK, Value: v, ServerTimestamp: ts},
			{Status: ua.StatusOK, Value: v, ServerTimestamp: ts},
			{Status: ua.StatusBad},
		},
	}

	out := ToPointsData(points, data, resp)
	assert.Equal(t, 3, len(out))

	// Configured point name has highest priority
	assert.Equal(t, "Temperature", out[0].Name)
	assert.Equal(t, 23.5, out[0].Value)
	assert.Equal(t, ts.UnixNano(), out[0].Timestamp)
	assert.Empty(t, out[0].Error)

	// DisplayName is secondary when no configured name
	assert.Equal(t, "Pressure", out[1].Name)

	// Bad point: use Addr when no DisplayName, Error filled, Value/Timestamp are zero values
	assert.Equal(t, "ns=2;s=C", out[2].Name)
	assert.NotEmpty(t, out[2].Error)
	assert.Nil(t, out[2].Value)
	assert.Equal(t, int64(0), out[2].Timestamp)

	// Unnamed points (endpoint scenario with only Addr) fallback to DisplayName → Addr
	out2 := ToPointsData([]iot_points.Point{{Addr: "ns=2;s=A"}, {Addr: "ns=2;s=B"}, {Addr: "ns=2;s=C"}}, data, resp)
	assert.Equal(t, "Temp", out2[0].Name)
	assert.Equal(t, "ns=2;s=C", out2[2].Name)

	// Apply Scale/Offset engineering conversion to values (23.5*2+1=48)
	scaled := []iot_points.Point{{Name: "Temperature", Addr: "ns=2;s=A", Scale: 2, Offset: 1}, {Addr: "ns=2;s=B"}, {Addr: "ns=2;s=C"}}
	out3 := ToPointsData(scaled, data, resp)
	assert.Equal(t, 48.0, out3[0].Value)
}

// TestToPointsDataSourceTimestampFallback: when ServerTimestamp is zero but SourceTimestamp is
// set (common for embedded/edge servers), the unified Data.Timestamp must still be populated.
func TestToPointsDataSourceTimestampFallback(t *testing.T) {
	points := []iot_points.Point{{Name: "Temp", Addr: "ns=2;s=A"}}
	data := []Data{{NodeId: "ns=2;s=A"}}
	srcTs := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	v, _ := ua.NewVariant(10.0)
	// Only SourceTimestamp set; ServerTimestamp left zero.
	resp := &ua.ReadResponse{
		Results: []*ua.DataValue{
			{Status: ua.StatusOK, Value: v, SourceTimestamp: srcTs},
		},
	}
	out := ToPointsData(points, data, resp)
	assert.Equal(t, 1, len(out))
	assert.Equal(t, srcTs.UnixNano(), out[0].Timestamp)
}

// TestParseValueUnsupportedReturnsReceiver: an unsupported value type must return the receiver
// (not nil) plus an error, so callers using the returned *Data do not nil-deref.
func TestParseValueUnsupportedReturnsReceiver(t *testing.T) {
	d := &Data{Value: []int{1, 2, 3}}
	got, err := d.ParseValue()
	assert.NotNil(t, got, "ParseValue must return the receiver, not nil, on unsupported type")
	assert.Equal(t, d, got)
	assert.NotNil(t, err)
}

// TestParseValueNilValueReturnsReceiver: a nil value must return the receiver plus an error.
func TestParseValueNilValueReturnsReceiver(t *testing.T) {
	d := &Data{Value: nil}
	got, err := d.ParseValue()
	assert.NotNil(t, got)
	assert.NotNil(t, err)
}
