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

// Package timescaledb provides TimescaleDB time-series database write and query nodes,
// with driver adapter to pkg/tsdb.Driver.
package timescaledb

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
)

// driver adapts tsdb.SeriesPoint to TimescaleDB using SQL INSERT.
type driver struct {
	db *sql.DB
}

var _ tsdb.Driver = (*driver)(nil)

// NewDriver creates a new TimescaleDB tsdb.Driver
func NewDriver(db *sql.DB) *driver {
	return &driver{db: db}
}

// newDriver is for internal backward compatibility
func newDriver(db *sql.DB) *driver {
	return &driver{db: db}
}

// 以下两个函数把 PostgreSQL 方言参数（双引号标识符、标准字符串转义）绑定到 pkg/tsdb 通用实现。

func quoteIdentifier(s string) string { return tsdb.QuoteIdentifier(s, '"') }

func formatValue(v interface{}) string { return tsdb.FormatValue(v, false) }

func validFieldValue(v interface{}) bool { return tsdb.ValidFieldValue(v) }

// maxStatementBytes 单条 INSERT 的字节预算。
const maxStatementBytes = 1024 * 1024

const insertPrefix = "INSERT INTO "

// rowGroup 同一 measurement 的一组点（tags 与 fields 均作为普通列）。
type rowGroup struct {
	measurement string
	colSet      map[string]struct{}
	rows        []groupRow
}

// groupRow 单行：各列取值（tag 为 string，field 为任意）与时间戳。
type groupRow struct {
	ts     int64
	values map[string]interface{}
}

// buildInsertStatements 按 measurement 分组拼装多 VALUES INSERT，并按字节预算拆条。
// PostgreSQL 单条 INSERT 只能面向一张表，故不同 measurement 不合并到同一条语句。
// 无可写点（输入为空或全部无有效列）时返回 nil。
func buildInsertStatements(db string, points []tsdb.SeriesPoint) []string {
	groups := make(map[string]*rowGroup)
	var order []string
	for i := range points {
		p := points[i]
		// 跳过无任何可写列的点（无 tag 且 field 全部无效）
		hasTag := len(p.Tags) > 0
		hasValidField := false
		for _, v := range p.Fields {
			if validFieldValue(v) {
				hasValidField = true
				break
			}
		}
		if !hasTag && !hasValidField {
			continue
		}
		g, exists := groups[p.Measurement]
		if !exists {
			g = &rowGroup{measurement: p.Measurement, colSet: make(map[string]struct{})}
			groups[p.Measurement] = g
			order = append(order, p.Measurement)
		}
		row := groupRow{ts: p.Timestamp, values: make(map[string]interface{}, len(p.Tags)+len(p.Fields))}
		for k, v := range p.Tags {
			g.colSet[k] = struct{}{}
			row.values[k] = v
		}
		for k, v := range p.Fields {
			if validFieldValue(v) {
				g.colSet[k] = struct{}{}
				row.values[k] = v
			}
		}
		g.rows = append(g.rows, row)
	}

	// 每个组独立成条（PG 单表限制），同组多行拼多 VALUES，超预算则拆条。
	var stmts []string
	for _, m := range order {
		for _, seg := range groupSegments(db, groups[m]) {
			stmts = append(stmts, insertPrefix+seg)
		}
	}
	return stmts
}

// groupSegments 渲染一个组为若干表段：列头出现一次后接多行 VALUES，缺失列补 NULL。
// 单组累计超过 maxStatementBytes 时断开另起段（重列头）。
func groupSegments(db string, g *rowGroup) []string {
	cols := sortedSetKeys(g.colSet)
	head := tableHeader(db, g.measurement, cols)
	var segs []string
	var b strings.Builder
	b.WriteString(head)
	n := 0
	for _, row := range g.rows {
		r := renderRow(row, cols)
		if n > 0 && b.Len()+1+len(r) > maxStatementBytes {
			segs = append(segs, b.String())
			b.Reset()
			b.WriteString(head)
			n = 0
		}
		if n > 0 {
			b.WriteString(",")
		}
		b.WriteString(r)
		n++
	}
	return append(segs, b.String())
}

// tableHeader 渲染列头：schema.measurement (业务列...,time) VALUES 。
func tableHeader(db, measurement string, cols []string) string {
	var b strings.Builder
	b.WriteString(quoteIdentifier(db))
	b.WriteString(".")
	b.WriteString(quoteIdentifier(measurement))
	b.WriteString(" (")
	for _, c := range cols {
		b.WriteString(quoteIdentifier(c))
		b.WriteString(",")
	}
	b.WriteString(quoteIdentifier("time"))
	b.WriteString(") VALUES ")
	return b.String()
}

// renderRow 渲染单行 VALUES：业务列值在前，时间戳在后，缺失列补 NULL。
func renderRow(row groupRow, cols []string) string {
	var b strings.Builder
	b.WriteString("(")
	for i, c := range cols {
		if i > 0 {
			b.WriteString(",")
		}
		if v, ok := row.values[c]; ok {
			b.WriteString(formatValue(v))
		} else {
			b.WriteString("NULL")
		}
	}
	b.WriteString(",")
	b.WriteString(formatTimestamp(row.ts))
	b.WriteString(")")
	return b.String()
}

// formatTimestamp 纳秒时间戳格式化；0 返回 NOW()。
func formatTimestamp(ts int64) string {
	if ts == 0 {
		return "NOW()"
	}
	return fmt.Sprintf("to_timestamp(%d/1000000000.0)", ts)
}

// sortedSetKeys 返回集合键的排序切片，保证列顺序确定。
func sortedSetKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// WritePoints 批量写入：拼装多 VALUES INSERT，在单个事务内逐条执行，任一失败回滚。
func (d *driver) WritePoints(ctx context.Context, db string, points []tsdb.SeriesPoint) error {
	stmts := buildInsertStatements(db, points)
	if len(stmts) == 0 {
		if len(points) == 0 {
			return nil
		}
		return fmt.Errorf("timescaledb: all %d point(s) skipped, no valid fields", len(points))
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
		}
	}()
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Query executes SQL query on TimescaleDB.
func (d *driver) Query(ctx context.Context, db, sqlStr string) (*tsdb.QueryResult, error) {
	rows, err := d.db.QueryContext(ctx, sqlStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return tsdb.ScanRows(rows)
}

// Close closes the TimescaleDB database connection.
func (d *driver) Close() error {
	return d.db.Close()
}
