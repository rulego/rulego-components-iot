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

// resolvePoints 双入口：兼容旧 read nodeIds 数组、旧 write {nodeId,value}、新 points，回退配置。
func TestResolvePoints(t *testing.T) {
	sentinel := errors.New("empty")
	config := []iot_points.Point{{Name: "cfg", Addr: "ns=2;s=Cfg"}}

	// 旧 read 格式：nodeId 字符串数组
	pts, err := resolvePoints(config, newPointsMsg(`["ns=2;s=A","ns=2;s=B"]`), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(pts))
	assert.Equal(t, "ns=2;s=A", pts[0].Addr)
	assert.Equal(t, "ns=2;s=B", pts[1].Addr)

	// 旧 write 格式：{nodeId,value,dataType}
	pts, err = resolvePoints(config, newPointsMsg(`[{"nodeId":"ns=2;s=X","value":1.5,"dataType":"Double"}]`), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "ns=2;s=X", pts[0].Addr)
	assert.Equal(t, "1.5", pts[0].Value)
	assert.Equal(t, "Double", pts[0].Type)

	// 新点位格式：{name,addr,type}
	pts, err = resolvePoints(config, newPointsMsg(`[{"name":"t","addr":"ns=2;s=T","type":"FLOAT64"}]`), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "t", pts[0].Name)
	assert.Equal(t, "ns=2;s=T", pts[0].Addr)
	assert.Equal(t, "FLOAT64", pts[0].Type)

	// msg.Data 空 -> 配置
	pts, err = resolvePoints(config, newPointsMsg(""), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "cfg", pts[0].Name)

	// null/[] -> 配置
	pts, err = resolvePoints(config, newPointsMsg("null"), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "cfg", pts[0].Name)
	pts, err = resolvePoints(config, newPointsMsg("[]"), sentinel)
	assert.Nil(t, err)
	assert.Equal(t, "cfg", pts[0].Name)

	// 都空 -> sentinel；emptyErr=nil -> 默认错误
	_, err = resolvePoints(nil, newPointsMsg(""), sentinel)
	assert.Equal(t, sentinel, err)
	_, err = resolvePoints(nil, newPointsMsg(""), nil)
	assert.NotNil(t, err)
}

// parseValue 把字符串值还原为 Go 值（标量/数组），复用 castValue。
func TestParseValue(t *testing.T) {
	assert.Equal(t, float64(1.5), parseValue("1.5", "double")) // 标量 double
	assert.Equal(t, int32(1), parseValue("1", "int32"))        // json 数值 -> float64 -> int32
	assert.Equal(t, true, parseValue("true", "boolean"))       // 布尔
	assert.Equal(t, "abc", parseValue(`"abc"`, "string"))      // JSON 字符串
	assert.Equal(t, "abc", parseValue("abc", "string"))        // 纯文本兜底
	assert.Equal(t, "", parseValue("", "string"))              // 空串

	// 数组 double
	v := parseValue("[1,2,3]", "double")
	arr, ok := v.([]float64)
	assert.True(t, ok)
	assert.Equal(t, []float64{1, 2, 3}, arr)

	// 数组 int32
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
	assert.Equal(t, "Double", mapType("Double")) // 未知/旧 dataType 透传
	assert.Equal(t, "", mapType(""))
}

// legacyDataToPoints 数组值经 json 序列化往返无损。
func TestLegacyDataToPoints(t *testing.T) {
	ds := []opcuaClient.Data{
		{NodeId: "ns=2;s=Arr", Value: []interface{}{float64(0), float64(60), float64(0)}, DataType: "Double"},
		{NodeId: "ns=2;s=Scalar", Value: float64(3.5), DataType: "Double"},
	}
	pts := legacyDataToPoints(ds)
	assert.Equal(t, 2, len(pts))
	assert.Equal(t, "ns=2;s=Arr", pts[0].Addr)
	assert.Equal(t, "Double", pts[0].Type)

	// 数组往返：Value 序列化为 JSON 数组，parseValue 还原为 []float64
	arr, ok := parseValue(pts[0].Value, mapType(pts[0].Type)).([]float64)
	assert.True(t, ok)
	assert.Equal(t, []float64{0, 60, 0}, arr)

	// 标量往返
	assert.Equal(t, float64(3.5), parseValue(pts[1].Value, mapType(pts[1].Type)))
}
