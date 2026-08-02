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

package opcua

import (
	"errors"
	"testing"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	"github.com/stretchr/testify/assert"
)

func newPointsMsg(data string) types.RuleMsg {
	return types.NewMsg(0, "test", types.JSON, types.NewMetadata(), data)
}

// resolvePoints dual entry: compat legacy read nodeIds array, legacy write {nodeId,value}, new points, fallback config.
func TestResolvePoints(t *testing.T) {
	sentinel := errors.New("empty")
	config := []iot_points.Point{{Name: "cfg", Addr: "ns=2;s=Cfg"}}

	// Legacy read format: nodeId string array
	pts, err := resolvePoints(config, newPointsMsg(`["ns=2;s=A","ns=2;s=B"]`), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(pts))
	assert.Equal(t, "ns=2;s=A", pts[0].Addr)
	assert.Equal(t, "ns=2;s=B", pts[1].Addr)

	// Legacy write format: {nodeId,value,dataType}
	pts, err = resolvePoints(config, newPointsMsg(`[{"nodeId":"ns=2;s=X","value":1.5,"dataType":"Double"}]`), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "ns=2;s=X", pts[0].Addr)
	assert.Equal(t, "1.5", pts[0].Value)
	assert.Equal(t, "Double", pts[0].Type)

	// New point format: {name,addr,type}
	pts, err = resolvePoints(config, newPointsMsg(`[{"name":"t","addr":"ns=2;s=T","type":"FLOAT64"}]`), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "t", pts[0].Name)
	assert.Equal(t, "ns=2;s=T", pts[0].Addr)
	assert.Equal(t, "FLOAT64", pts[0].Type)

	// msg.Data empty -> config
	pts, err = resolvePoints(config, newPointsMsg(""), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "cfg", pts[0].Name)

	// null/[] -> config
	pts, err = resolvePoints(config, newPointsMsg("null"), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "cfg", pts[0].Name)
	pts, err = resolvePoints(config, newPointsMsg("[]"), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "cfg", pts[0].Name)

	// Both empty -> sentinel; emptyErr=nil -> default error
	_, err = resolvePoints(nil, newPointsMsg(""), sentinel)
	assert.Equal(t, sentinel, err)
	_, err = resolvePoints(nil, newPointsMsg(""), nil)
	assert.NotNil(t, err)
}

// parseValue converts string value back to Go value (scalar/array), reusing castValue.
func TestParseValue(t *testing.T) {
	assert.Equal(t, float64(1.5), parseValue("1.5", "double")) // scalar double
	assert.Equal(t, int32(1), parseValue("1", "int32"))        // json number -> float64 -> int32
	assert.Equal(t, true, parseValue("true", "boolean"))       // boolean
	assert.Equal(t, "abc", parseValue(`"abc"`, "string"))      // JSON string
	assert.Equal(t, "abc", parseValue("abc", "string"))        // plain text fallback
	assert.Equal(t, "", parseValue("", "string"))              // empty string

	// Array double
	v := parseValue("[1,2,3]", "double")
	arr, ok := v.([]float64)
	assert.True(t, ok)
	assert.Equal(t, []float64{1, 2, 3}, arr)

	// Array int32
	v = parseValue("[1,2,3]", "int32")
	iarr, ok := v.([]int32)
	assert.True(t, ok)
	assert.Equal(t, []int32{1, 2, 3}, iarr)
}

func TestMapType(t *testing.T) {
	assert.Equal(t, "double", mapType(iot_points.TypeFloat64))
	assert.Equal(t, "boolean", mapType(iot_points.TypeBool))
	assert.Equal(t, "int32", mapType(iot_points.TypeInt32))
	assert.Equal(t, "uint16", mapType(iot_points.TypeUint16))
	assert.Equal(t, "Double", mapType("Double")) // unknown/legacy dataType passthrough
	assert.Equal(t, "", mapType(""))
}

// legacyDataToPoints array values survive json serialization roundtrip lossless.
func TestLegacyDataToPoints(t *testing.T) {
	ds := []opcuaClient.Data{
		{NodeId: "ns=2;s=Arr", Value: []interface{}{float64(0), float64(60), float64(0)}, DataType: "Double"},
		{NodeId: "ns=2;s=Scalar", Value: float64(3.5), DataType: "Double"},
	}
	pts := legacyDataToPoints(ds)
	assert.Equal(t, 2, len(pts))
	assert.Equal(t, "ns=2;s=Arr", pts[0].Addr)
	assert.Equal(t, "Double", pts[0].Type)

	// Array roundtrip: Value serialized as JSON array, parseValue restores to []float64
	arr, ok := parseValue(pts[0].Value, mapType(pts[0].Type)).([]float64)
	assert.True(t, ok)
	assert.Equal(t, []float64{0, 60, 0}, arr)

	// Scalar roundtrip
	assert.Equal(t, float64(3.5), parseValue(pts[1].Value, mapType(pts[1].Type)))
}
