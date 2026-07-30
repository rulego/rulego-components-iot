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

package timescaledb

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
)

const testTS = int64(1700000000000000000)

// TestBuildInsertStatementsSinglePoint 单点：tags/fields/time 列齐全，与单点 INSERT 格式一致。
func TestBuildInsertStatementsSinglePoint(t *testing.T) {
	stmts := buildInsertStatements("public", []tsdb.SeriesPoint{{
		Measurement: "cpu",
		Tags:        map[string]string{"host": "srv1"},
		Fields:      map[string]interface{}{"value": 72.5},
		Timestamp:   testTS,
	}})
	assert.Equal(t, []string{
		"INSERT INTO \"public\".\"cpu\" (\"host\",\"value\",\"time\") VALUES ('srv1',72.5,to_timestamp(1700000000000000000/1000000000.0))",
	}, stmts)
}

// TestBuildInsertStatementsZeroTimestamp ts=0 用 NOW()。
func TestBuildInsertStatementsZeroTimestamp(t *testing.T) {
	stmts := buildInsertStatements("public", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"value": 1}},
	})
	assert.Contains(t, stmts[0], "NOW()")
	assert.NotContains(t, stmts[0], "to_timestamp")
}

// TestBuildInsertStatementsNonZeroTimestamp ts!=0 用 to_timestamp。
func TestBuildInsertStatementsNonZeroTimestamp(t *testing.T) {
	stmts := buildInsertStatements("public", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"value": 1}, Timestamp: testTS},
	})
	assert.Contains(t, stmts[0], "to_timestamp(1700000000000000000/1000000000.0)")
	assert.NotContains(t, stmts[0], "NOW()")
}

// TestBuildInsertStatementsEscapesStrings 字符串值单引号翻倍转义（PG 方言）。
func TestBuildInsertStatementsEscapesStrings(t *testing.T) {
	stmts := buildInsertStatements("public", []tsdb.SeriesPoint{
		{Measurement: "cpu", Tags: map[string]string{"note": "O'Neil"}, Fields: map[string]interface{}{"value": 1}},
	})
	assert.Contains(t, stmts[0], "'O''Neil'")
}

// TestBuildInsertStatementsMultiRows 同表多行合并为一条语句的多行 VALUES。
func TestBuildInsertStatementsMultiRows(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"v": 1.0}, Timestamp: testTS},
		{Measurement: "cpu", Fields: map[string]interface{}{"v": 2.0}, Timestamp: testTS},
	})
	tsLit := formatTimestamp(testTS)
	assert.Equal(t, []string{
		"INSERT INTO \"iot\".\"cpu\" (\"v\",\"time\") VALUES (1," + tsLit + "),(2," + tsLit + ")",
	}, stmts)
}

// TestBuildInsertStatementsColumnSuperset 同表不同字段集：列取超集、缺失补 NULL、列头只出现一次。
func TestBuildInsertStatementsColumnSuperset(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"v": 1.5}, Timestamp: testTS},
		{Measurement: "cpu", Fields: map[string]interface{}{"q": 2.0, "v": 3.0}, Timestamp: testTS},
	})
	tsLit := formatTimestamp(testTS)
	assert.Equal(t, []string{
		"INSERT INTO \"iot\".\"cpu\" (\"q\",\"v\",\"time\") VALUES (NULL,1.5," + tsLit + "),(2,3," + tsLit + ")",
	}, stmts)
	assert.Equal(t, 1, strings.Count(stmts[0], "\"cpu\" ("))
}

// TestBuildInsertStatementsMultipleMeasurements 不同 measurement 各自成独立 INSERT（PG 单表限制）。
func TestBuildInsertStatementsMultipleMeasurements(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"v": 1.0}},
		{Measurement: "mem", Fields: map[string]interface{}{"v": 2.0}},
	})
	assert.Len(t, stmts, 2)
	assert.True(t, strings.HasPrefix(stmts[0], "INSERT INTO \"iot\".\"cpu\" "))
	assert.True(t, strings.HasPrefix(stmts[1], "INSERT INTO \"iot\".\"mem\" "))
}

// TestBuildInsertStatementsSkipsInvalid nil/NaN 字段跳过；无有效列的点整体跳过。
func TestBuildInsertStatementsSkipsInvalid(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "m", Fields: map[string]interface{}{"a": nil, "b": 1.0}},
		{Measurement: "m2", Fields: map[string]interface{}{"a": math.NaN()}},
	})
	assert.Equal(t, []string{
		"INSERT INTO \"iot\".\"m\" (\"b\",\"time\") VALUES (1,NOW())",
	}, stmts)
	assert.Empty(t, buildInsertStatements("iot", nil))
}

// TestBuildInsertStatementsChunking 大批量按字节预算拆分多条语句，行数不丢。
func TestBuildInsertStatementsChunking(t *testing.T) {
	const total = 30000
	points := make([]tsdb.SeriesPoint, 0, total)
	for i := 0; i < total; i++ {
		points = append(points, tsdb.SeriesPoint{
			Measurement: "cpu",
			Tags:        map[string]string{"id": fmt.Sprintf("dev%05d", i)},
			Fields:      map[string]interface{}{"v": float64(i)},
			Timestamp:   testTS,
		})
	}
	stmts := buildInsertStatements("iot", points)
	assert.Greater(t, len(stmts), 1)
	tsLit := formatTimestamp(testTS)
	rows := 0
	for _, s := range stmts {
		assert.LessOrEqual(t, len(s), maxStatementBytes+2048)
		assert.True(t, strings.HasPrefix(s, "INSERT INTO "))
		rows += strings.Count(s, tsLit)
	}
	assert.Equal(t, total, rows)
}

// TestFormatTimestamp ts=0 为 NOW()，否则为 to_timestamp 字面量。
func TestFormatTimestamp(t *testing.T) {
	assert.Equal(t, "NOW()", formatTimestamp(0))
	assert.Equal(t, "to_timestamp(1700000000000000000/1000000000.0)", formatTimestamp(testTS))
}

// TestWritePointsAllSkipped 点全部无效时返回错误；空输入无操作。
func TestWritePointsAllSkipped(t *testing.T) {
	d := newDriver(&sql.DB{})
	err := d.WritePoints(context.Background(), "iot", []tsdb.SeriesPoint{
		{Measurement: "m", Fields: map[string]interface{}{"a": nil}},
	})
	assert.Error(t, err)
	assert.Nil(t, d.WritePoints(context.Background(), "iot", nil))
}

// TestBuildInsertStatementsSkipsEmptyMeasurement 空 measurement 的点跳过。
func TestBuildInsertStatementsSkipsEmptyMeasurement(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "", Fields: map[string]interface{}{"v": 1.0}},
		{Measurement: "cpu", Fields: map[string]interface{}{"v": 2.0}},
	})
	assert.Equal(t, []string{
		"INSERT INTO \"iot\".\"cpu\" (\"v\",\"time\") VALUES (2,NOW())",
	}, stmts)
}

// TestBuildInsertStatementsReservedColumn 名为 time 的业务列被剔除，避免与时间列重复。
func TestBuildInsertStatementsReservedColumn(t *testing.T) {
	stmts := buildInsertStatements("iot", []tsdb.SeriesPoint{
		{Measurement: "cpu", Fields: map[string]interface{}{"time": 1, "v": 2.0}},
		{Measurement: "cpu", Tags: map[string]string{"time": "x"}, Fields: map[string]interface{}{"v": 3.0}},
	})
	assert.Equal(t, []string{
		"INSERT INTO \"iot\".\"cpu\" (\"v\",\"time\") VALUES (2,NOW()),(3,NOW())",
	}, stmts)
	assert.Equal(t, 1, strings.Count(stmts[0], "\"time\""))
}
