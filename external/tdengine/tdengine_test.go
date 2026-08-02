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

	// Numeric values without i suffix are parsed as float64 per line protocol standard
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
	// Floats do not use scientific notation
	assert.Equal(t, "1000000", formatValue(float64(1000000)))
	assert.Equal(t, "'O\\'Neil'", formatValue("O'Neil"))
	// TDengine dialect doubles backslashes
	assert.Equal(t, "'C:\\\\new'", formatValue("C:\\new"))
	// Nested objects serialized as JSON strings
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

// TestBuildInsertStatementsStable super table mode: same table segment merges multiple rows, different tags split table segments, ts=0 uses NOW().
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

// TestBuildInsertStatementsNormalTable without tags: writes to normal table of same name.
func TestBuildInsertStatementsNormalTable(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"usage": float64(12)}, Timestamp: 0},
	})
	assert.Equal(t, []string{"INSERT INTO `iot`.`cpu` (`ts`,`usage`) VALUES (NOW(),12)"}, stmts)
}

// TestBuildInsertStatementsReservedColumn business column named ts is excluded to avoid duplication with timestamp column.
func TestBuildInsertStatementsReservedColumn(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"ts": 1, "v": 2.0}},
	})
	assert.Equal(t, []string{"INSERT INTO `iot`.`cpu` (`ts`,`v`) VALUES (NOW(),2)"}, stmts)
}

// TestBuildInsertStatementsReservedTag degrades to normal table when only tag is ts and gets excluded.
func TestBuildInsertStatementsReservedTag(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Tags: map[string]string{"ts": "x"}, Fields: map[string]interface{}{"v": 2.0}},
	})
	assert.Len(t, stmts, 1)
	assert.NotContains(t, stmts[0], "USING")
	assert.Equal(t, "INSERT INTO `iot`.`cpu` (`ts`,`v`) VALUES (NOW(),2)", stmts[0])
}

// TestBuildInsertStatementsSkipsInvalid nil/NaN fields are skipped; points with no valid fields are skipped entirely.
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

// TestBuildInsertStatementsColumnSuperset same table segment with different field sets: columns take superset, missing filled with NULL, table segment appears only once.
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

// TestBuildInsertStatementsChunking large batches split into multiple statements by byte budget, no rows lost.
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

// TestPointTarget with multiple tags sorts by key; skipped when timestamp out of range or no valid fields.
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
	assert.False(t, ok, "skipped: timestamp out of range")
	_, _, ok = pointTarget("iot", tsdb.SeriesPoint{Measurement: "m", Fields: map[string]interface{}{"f": math.NaN()}})
	assert.False(t, ok, "skipped: no valid field")
	_, _, ok = pointTarget("iot", tsdb.SeriesPoint{Measurement: "", Fields: map[string]interface{}{"f": 1.0}})
	assert.False(t, ok, "skipped: empty measurement")
}

func TestSubTableName(t *testing.T) {
	tagsA := map[string]string{"id": "dev-01"}
	tagsB := map[string]string{"id": "dev_01"}
	nameA := subTableName("meters", tagsA, []string{"id"})
	nameB := subTableName("meters", tagsB, []string{"id"})
	// Sanitized prefixes are same but hash suffixes differ, avoiding collision merge into wrong table
	assert.True(t, strings.HasPrefix(nameA, "meters_dev_01_"), nameA)
	assert.True(t, strings.HasPrefix(nameB, "meters_dev_01_"), nameB)
	assert.NotEqual(t, nameA, nameB)
	// Special chars replaced with underscores, digit-prefixed names get leading underscore
	assert.True(t, strings.HasPrefix(subTableName("m", map[string]string{"id": "dev-01", "site": "A."}, []string{"id", "site"}), "m_dev_01_A__"))
	assert.True(t, strings.HasPrefix(subTableName("1a", nil, nil), "_1a_"))
	// Total length not exceeding 192 bytes
	long := subTableName(strings.Repeat("x", 300), nil, nil)
	assert.LessOrEqual(t, len(long), 192)
}

func TestFormatTimestamp(t *testing.T) {
	assert.Equal(t, "NOW()", formatTimestamp(0))
	ts := int64(1700000000000000000)
	// ISO8601 literal with timezone offset (local timezone independent)
	expected := "'" + time.Unix(0, ts).Format("2006-01-02T15:04:05.000000000-07:00") + "'"
	assert.Equal(t, expected, formatTimestamp(ts))
}

// TestWritePointsAllSkipped returns error when all points invalid, does not silently succeed; empty input is no-op.
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
