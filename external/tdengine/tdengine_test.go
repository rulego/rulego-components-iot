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

package tdengine

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/utils/el"
	"github.com/stretchr/testify/assert"
)

func TestParseLine(t *testing.T) {
	// With timestamp
	p, err := tsdb.ParseLine("cpu,host=srv1 value=72.5 1700000000000000000")
	assert.Nil(t, err)
	assert.Equal(t, "cpu", p.Measurement)
	assert.Equal(t, "srv1", p.Tags["host"])
	assert.Equal(t, 72.5, p.Fields["value"])
	assert.Equal(t, int64(1700000000000000000), p.Timestamp)

	// Without timestamp -> use current time
	p2, err := tsdb.ParseLine("temp,loc=a v=23")
	assert.Nil(t, err)
	assert.NotEqual(t, int64(0), p2.Timestamp)

	// 无 i 后缀的数值按 line protocol 标准解析为 float64
	p3, err := tsdb.ParseLine("m,k=v f=100")
	assert.Nil(t, err)
	assert.Equal(t, float64(100), p3.Fields["f"])
}

func TestParseLineProtocol(t *testing.T) {
	pts, err := tsdb.ParseLineProtocol("cpu,host=a v=1 100\ncpu,host=b v=2 200\n\n")
	assert.Nil(t, err)
	assert.Equal(t, 2, len(pts))
	assert.Equal(t, "a", pts[0].Tags["host"])
	assert.Equal(t, "b", pts[1].Tags["host"])
}

func TestParseMsgPointsJSON(t *testing.T) {
	msg := types.NewMsg(0, "test", types.JSON, types.NewMetadata(),
		`[{"measurement":"cpu","tags":{"h":"a"},"fields":{"v":1},"timestamp":100}]`)
	pts, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "cpu", pts[0].Measurement)
	assert.Equal(t, "a", pts[0].Tags["h"])
	assert.Equal(t, int64(100), pts[0].Timestamp)
}

func TestParseMsgPointsLine(t *testing.T) {
	msg := types.NewMsg(0, "test", types.TEXT, types.NewMetadata(), "cpu,host=a v=1 100")
	pts, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "cpu", pts[0].Measurement)
}

func TestFormatValue(t *testing.T) {
	assert.Equal(t, "'test'", formatValue("test"))
	assert.Equal(t, "123", formatValue(123))
	assert.Equal(t, "123.45", formatValue(123.45))
	assert.Equal(t, "TRUE", formatValue(true))
	assert.Equal(t, "FALSE", formatValue(false))
}

func TestFormatValueExtended(t *testing.T) {
	assert.Equal(t, "NULL", formatValue(nil))
	// 浮点数不使用科学计数法
	assert.Equal(t, "1000000", formatValue(float64(1000000)))
	assert.Equal(t, "'O\\'Neil'", formatValue("O'Neil"))
	// TDengine 方言反斜杠翻倍
	assert.Equal(t, "'C:\\\\new'", formatValue("C:\\new"))
	// 嵌套对象序列化为 JSON 字符串
	assert.Equal(t, "'{\"a\":1}'", formatValue(map[string]interface{}{"a": 1}))
}

func TestValidFieldValue(t *testing.T) {
	assert.False(t, validFieldValue(nil))
	assert.False(t, validFieldValue(math.NaN()))
	assert.False(t, validFieldValue(math.Inf(1)))
	assert.False(t, validFieldValue(math.Inf(-1)))
	assert.True(t, validFieldValue(1.0))
	assert.True(t, validFieldValue(0.0))
	assert.True(t, validFieldValue("s"))
	assert.True(t, validFieldValue(1))
	assert.True(t, validFieldValue(false))
}

// TestBuildInsertStatementsStable 超级表模式：同表段多行合并、不同 tags 拆表段、ts=0 用 NOW()。
func TestBuildInsertStatementsStable(t *testing.T) {
	ts := int64(1700000000000000000)
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "meters", Tags: map[string]string{"loc": "a"}, Fields: map[string]interface{}{"v": 1.5}, Timestamp: ts},
		{Measurement: "meters", Tags: map[string]string{"loc": "a"}, Fields: map[string]interface{}{"v": 2.5}, Timestamp: ts},
		{Measurement: "meters", Tags: map[string]string{"loc": "b"}, Fields: map[string]interface{}{"v": 3.5}, Timestamp: 0},
	})
	subA := subTableName("meters", map[string]string{"loc": "a"}, []string{"loc"})
	subB := subTableName("meters", map[string]string{"loc": "b"}, []string{"loc"})
	tsLit := formatTimestamp(ts)
	expected := "INSERT INTO `iot`.`" + subA + "` USING `iot`.`meters` (`loc`) TAGS ('a') (`ts`,`v`) VALUES (" +
		tsLit + ",1.5) (" + tsLit + ",2.5) " +
		"`iot`.`" + subB + "` USING `iot`.`meters` (`loc`) TAGS ('b') (`ts`,`v`) VALUES (NOW(),3.5)"
	assert.Equal(t, []string{expected}, stmts)
}

// TestBuildInsertStatementsNormalTable 无 tags：写入同名普通表。
func TestBuildInsertStatementsNormalTable(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"usage": float64(12)}, Timestamp: 0},
	})
	assert.Equal(t, []string{"INSERT INTO `iot`.`cpu` (`ts`,`usage`) VALUES (NOW(),12)"}, stmts)
}

// TestBuildInsertStatementsReservedColumn 名为 ts 的业务列被剔除，避免与时间戳列重复。
func TestBuildInsertStatementsReservedColumn(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"ts": 1, "v": 2.0}},
	})
	assert.Equal(t, []string{"INSERT INTO `iot`.`cpu` (`ts`,`v`) VALUES (NOW(),2)"}, stmts)
}

// TestBuildInsertStatementsReservedTag 唯一 tag 为 ts 被剔除后退化为普通表。
func TestBuildInsertStatementsReservedTag(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Tags: map[string]string{"ts": "x"}, Fields: map[string]interface{}{"v": 2.0}},
	})
	assert.Len(t, stmts, 1)
	assert.NotContains(t, stmts[0], "USING")
	assert.Equal(t, "INSERT INTO `iot`.`cpu` (`ts`,`v`) VALUES (NOW(),2)", stmts[0])
}

// TestBuildInsertStatementsSkipsInvalid nil/NaN 字段跳过；无有效字段的点整体跳过。
func TestBuildInsertStatementsSkipsInvalid(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "m", Fields: map[string]interface{}{"a": nil, "b": 1.0}, Timestamp: 0},
		{Measurement: "m2", Fields: map[string]interface{}{"a": nil}, Timestamp: 0},
		{Measurement: "m3", Fields: map[string]interface{}{"a": math.NaN()}, Timestamp: 0},
		{Measurement: "m4", Fields: map[string]interface{}{"a": 1.0}, Timestamp: -1},
	})
	assert.Equal(t, []string{"INSERT INTO `iot`.`m` (`ts`,`b`) VALUES (NOW(),1)"}, stmts)
	assert.Empty(t, buildInsertStatements("iot", nil))
}

// TestBuildInsertStatementsColumnSuperset 同表段不同字段集：列取超集、缺失补 NULL、表段只出现一次。
func TestBuildInsertStatementsColumnSuperset(t *testing.T) {
	ts := int64(1700000000000000000)
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "meters", Tags: map[string]string{"loc": "a"}, Fields: map[string]interface{}{"v": 1.5}, Timestamp: ts},
		{Measurement: "meters", Tags: map[string]string{"loc": "a"}, Fields: map[string]interface{}{"q": 2.0, "v": 3.0}, Timestamp: ts},
	})
	sub := subTableName("meters", map[string]string{"loc": "a"}, []string{"loc"})
	tsLit := formatTimestamp(ts)
	expected := "INSERT INTO `iot`.`" + sub + "` USING `iot`.`meters` (`loc`) TAGS ('a') (`ts`,`q`,`v`) VALUES (" +
		tsLit + ",NULL,1.5) (" + tsLit + ",2,3)"
	assert.Equal(t, []string{expected}, stmts)
	assert.Equal(t, 1, strings.Count(stmts[0], "USING"))
}

// TestBuildInsertStatementsChunking 大批量按字节预算拆分为多条语句，行数不丢。
func TestBuildInsertStatementsChunking(t *testing.T) {
	const total = 20000
	ts := int64(1700000000000000000)
	points := make([]tsdb.SeriesPoint, 0, total)
	for i := 0; i < total; i++ {
		points = append(points, tsdb.SeriesPoint{
			Measurement: "meters",
			Tags:        map[string]string{"id": fmt.Sprintf("dev%05d", i)},
			Fields:      map[string]interface{}{"v": float64(i)},
			Timestamp:   ts,
		})
	}
	stmts := buildInsertStatements("iot", points)
	assert.Greater(t, len(stmts), 1)
	rows := 0
	for _, s := range stmts {
		assert.LessOrEqual(t, len(s), maxStatementBytes+2048)
		assert.True(t, strings.HasPrefix(s, "INSERT INTO "))
		rows += strings.Count(s, formatTimestamp(ts)+",")
	}
	assert.Equal(t, total, rows)
}

// TestPointTarget 多 tag 时按 key 排序；时间戳越界或无有效字段时跳过。
func TestPointTarget(t *testing.T) {
	p := tsdb.SeriesPoint{
		Measurement: "m",
		Tags:        map[string]string{"z": "1", "a": "2"},
		Fields:      map[string]interface{}{"f2": 2.0, "f1": 1.0},
	}
	key, target, ok := pointTarget("iot", p)
	assert.True(t, ok)
	assert.Equal(t, "m\x00a\x002\x00z\x001", key)
	sub := subTableName("m", p.Tags, []string{"a", "z"})
	assert.Equal(t, "`iot`.`"+sub+"` USING `iot`.`m` (`a`,`z`) TAGS ('2','1')", target)

	_, _, ok = pointTarget("iot", tsdb.SeriesPoint{Measurement: "m", Fields: map[string]interface{}{"f": 1.0}, Timestamp: -1})
	assert.False(t, ok, "时间戳越界跳过")
	_, _, ok = pointTarget("iot", tsdb.SeriesPoint{Measurement: "m", Fields: map[string]interface{}{"f": math.NaN()}})
	assert.False(t, ok, "无有效字段跳过")
	_, _, ok = pointTarget("iot", tsdb.SeriesPoint{Measurement: "", Fields: map[string]interface{}{"f": 1.0}})
	assert.False(t, ok, "空 measurement 跳过")
}

func TestSubTableName(t *testing.T) {
	tagsA := map[string]string{"id": "dev-01"}
	tagsB := map[string]string{"id": "dev_01"}
	nameA := subTableName("meters", tagsA, []string{"id"})
	nameB := subTableName("meters", tagsB, []string{"id"})
	// 净化前缀相同但哈希后缀不同，避免折叠碰撞串表
	assert.True(t, strings.HasPrefix(nameA, "meters_dev_01_"), nameA)
	assert.True(t, strings.HasPrefix(nameB, "meters_dev_01_"), nameB)
	assert.NotEqual(t, nameA, nameB)
	// 特殊字符替换为下划线、数字开头补下划线
	assert.True(t, strings.HasPrefix(subTableName("m", map[string]string{"id": "dev-01", "site": "A."}, []string{"id", "site"}), "m_dev_01_A__"))
	assert.True(t, strings.HasPrefix(subTableName("1a", nil, nil), "_1a_"))
	// 总长不超过 192 字节
	long := subTableName(strings.Repeat("x", 300), nil, nil)
	assert.LessOrEqual(t, len(long), 192)
}

func TestFormatTimestamp(t *testing.T) {
	assert.Equal(t, "NOW()", formatTimestamp(0))
	ts := int64(1700000000000000000)
	// 带时区偏移的 ISO8601 字面量（本地时区无关）
	expected := "'" + time.Unix(0, ts).Format("2006-01-02T15:04:05.000000000-07:00") + "'"
	assert.Equal(t, expected, formatTimestamp(ts))
}

// TestWritePointsAllSkipped 点全部无效时返回错误，不静默报成功；空输入为无操作。
func TestWritePointsAllSkipped(t *testing.T) {
	d := newDriver(&sql.DB{})
	err := d.WritePoints(context.Background(), "iot", []tsdb.SeriesPoint{
		{Measurement: "m", Fields: map[string]interface{}{"a": nil}},
	})
	assert.Error(t, err)
	assert.Nil(t, d.WritePoints(context.Background(), "iot", nil))
}

// TestWriteNodeOnMsg verifies that invalid payloads are routed to Failure before database execution.
func TestWriteNodeOnMsg(t *testing.T) {
	node := &WriteNode{
		Config: WriteConfig{
			DB: "db0",
		},
	}
	node.dbTemplate, _ = el.NewTemplate(node.Config.DB)
	err := node.SharedNode.InitWithClose(types.NewConfig(), node.Type(), "mock://tdengine", false, func() (*sql.DB, error) {
		return &sql.DB{}, nil
	}, func(db *sql.DB) error {
		return nil
	})
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{"measurement":"cpu"`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tdengine write callback")
	}
}

// TestQueryNodeOnMsg verifies that missing clients are routed to Failure.
func TestQueryNodeOnMsg(t *testing.T) {
	node := &QueryNode{
		WriteNode: &WriteNode{
			Config: WriteConfig{
				DB: "db0",
			},
		},
		Config: QueryConfig{
			DB:    "db0",
			Query: "select * from cpu_load",
		},
	}
	node.dbTemplate, _ = el.NewTemplate(node.Config.DB)
	node.queryTemplate, _ = el.NewTemplate(node.Config.Query)
	node.queryHasVar = node.queryTemplate.HasVar()

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.ErrorIs(t, err, base.ErrClientNotInit)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tdengine query callback")
	}
}
