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

// Package tdengine provides TDengine time-series database write and query nodes,
// with driver adapter to pkg/tsdb.Driver.
package tdengine

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
)

// driver adapts tsdb.SeriesPoint to TDengine using SQL INSERT.
type driver struct {
	db *sql.DB
}

var _ tsdb.Driver = (*driver)(nil)

// NewDriver creates a new TDengine tsdb.Driver
func NewDriver(db *sql.DB) *driver {
	return &driver{db: db}
}

// newDriver is for internal backward compatibility
func newDriver(db *sql.DB) *driver {
	return &driver{db: db}
}

// WritePoints 批量写入 SeriesPoint：带 tags 自动建子表，不带 tags 写同名普通表。
func (d *driver) WritePoints(ctx context.Context, db string, points []tsdb.SeriesPoint) error {
	stmts := buildInsertStatements(db, points)
	if len(stmts) == 0 {
		if len(points) == 0 {
			return nil
		}
		return fmt.Errorf("tdengine: all %d point(s) skipped, no valid fields or timestamp out of range", len(points))
	}
	for _, stmt := range stmts {
		if _, err := d.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// tableGroup 同一目标表段的一组点。
type tableGroup struct {
	target   string
	fieldSet map[string]struct{}
	rows     []seriesRow
}

// seriesRow 单行数据：时间戳 + 字段值。
type seriesRow struct {
	ts     int64
	fields map[string]interface{}
}

// TDengine 时间戳下限（纳秒）：1970-01-01T00:00:01Z。
const minTimestamp = int64(time.Second)

// maxStatementBytes 单条 INSERT 的字节预算。
const maxStatementBytes = 512 * 1024

const insertPrefix = "INSERT INTO "

// buildInsertStatements 拼装批量 INSERT 语句，按 maxStatementBytes 拆分，同表段字段取超集。
func buildInsertStatements(db string, points []tsdb.SeriesPoint) []string {
	groups := make(map[string]*tableGroup)
	var order []string
	for i := range points {
		key, target, ok := pointTarget(db, points[i])
		if !ok {
			continue
		}
		g, exists := groups[key]
		if !exists {
			g = &tableGroup{target: target, fieldSet: make(map[string]struct{})}
			groups[key] = g
			order = append(order, key)
		}
		for k, v := range points[i].Fields {
			if validFieldValue(v) {
				g.fieldSet[k] = struct{}{}
			}
		}
		g.rows = append(g.rows, seriesRow{ts: points[i].Timestamp, fields: points[i].Fields})
	}
	var segments []string
	for _, key := range order {
		segments = append(segments, groupSegments(groups[key])...)
	}
	var stmts []string
	var cur strings.Builder
	for _, seg := range segments {
		if cur.Len() > 0 && len(insertPrefix)+cur.Len()+1+len(seg) > maxStatementBytes {
			stmts = append(stmts, insertPrefix+cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteString(" ")
		}
		cur.WriteString(seg)
	}
	if cur.Len() > 0 {
		stmts = append(stmts, insertPrefix+cur.String())
	}
	return stmts
}

// groupSegments 渲染一个组为若干表段。
func groupSegments(g *tableGroup) []string {
	cols := sortedSetKeys(g.fieldSet)
	var header strings.Builder
	header.WriteString(g.target)
	header.WriteString(" (")
	header.WriteString(quoteIdentifier("ts"))
	for _, c := range cols {
		header.WriteString(",")
		header.WriteString(quoteIdentifier(c))
	}
	header.WriteString(") VALUES ")
	head := header.String()
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
			b.WriteString(" ")
		}
		b.WriteString(r)
		n++
	}
	return append(segs, b.String())
}

// renderRow 渲染单行 VALUES（缺失列补 NULL）。
func renderRow(row seriesRow, cols []string) string {
	var b strings.Builder
	b.WriteString("(")
	b.WriteString(formatTimestamp(row.ts))
	for _, c := range cols {
		b.WriteString(",")
		if v, ok := row.fields[c]; ok && validFieldValue(v) {
			b.WriteString(formatValue(v))
		} else {
			b.WriteString("NULL")
		}
	}
	b.WriteString(")")
	return b.String()
}

// pointTarget 生成点的分组键与表段目标；时间戳越界或无有效字段时 ok=false。
func pointTarget(db string, point tsdb.SeriesPoint) (string, string, bool) {
	if point.Timestamp != 0 && point.Timestamp < minTimestamp {
		return "", "", false
	}
	valid := false
	for _, v := range point.Fields {
		if validFieldValue(v) {
			valid = true
			break
		}
	}
	if !valid {
		return "", "", false
	}
	qdb := quoteIdentifier(db)
	if len(point.Tags) == 0 {
		return point.Measurement + "\x00", qdb + "." + quoteIdentifier(point.Measurement), true
	}
	tagKeys := make([]string, 0, len(point.Tags))
	for k := range point.Tags {
		tagKeys = append(tagKeys, k)
	}
	sort.Strings(tagKeys)
	tagCols := make([]string, 0, len(tagKeys))
	tagVals := make([]string, 0, len(tagKeys))
	keyParts := make([]string, 0, len(tagKeys)*2+1)
	keyParts = append(keyParts, point.Measurement)
	for _, k := range tagKeys {
		tagCols = append(tagCols, quoteIdentifier(k))
		tagVals = append(tagVals, formatValue(point.Tags[k]))
		keyParts = append(keyParts, k, point.Tags[k])
	}
	target := fmt.Sprintf("%s.%s USING %s.%s (%s) TAGS (%s)",
		qdb, quoteIdentifier(subTableName(point.Measurement, point.Tags, tagKeys)),
		qdb, quoteIdentifier(point.Measurement),
		strings.Join(tagCols, ","), strings.Join(tagVals, ","))
	return strings.Join(keyParts, "\x00"), target, true
}

// subTableName 生成子表名：净化前缀 + 8 位哈希后缀，总长不超过 192 字节。
func subTableName(measurement string, tags map[string]string, tagKeys []string) string {
	parts := make([]string, 0, len(tagKeys)+1)
	parts = append(parts, measurement)
	h := fnv.New32a()
	_, _ = h.Write([]byte(measurement))
	for _, k := range tagKeys {
		parts = append(parts, tags[k])
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(tags[k]))
	}
	suffix := fmt.Sprintf("%08x", h.Sum32())
	prefix := sanitizeIdent(strings.Join(parts, "_"))
	if max := 192 - len(suffix) - 1; len(prefix) > max {
		prefix = prefix[:max]
	}
	return prefix + "_" + suffix
}

// sanitizeIdent 替换非法字符为下划线，保证以字母或下划线开头。
func sanitizeIdent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if i == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// sortedSetKeys 返回集合键的排序切片，保证生成 SQL 的列顺序确定。
func sortedSetKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func quoteIdentifier(s string) string { return tsdb.QuoteIdentifier(s, '`') }

func formatValue(v interface{}) string { return tsdb.FormatValue(v, true) }

func validFieldValue(v interface{}) bool { return tsdb.ValidFieldValue(v) }

// formatTimestamp 纳秒时间戳格式化为带时区偏移的 ISO8601 字符串字面量；0 返回 NOW()。
func formatTimestamp(ts int64) string {
	if ts == 0 {
		return "NOW()"
	}
	return "'" + time.Unix(0, ts).Format("2006-01-02T15:04:05.000000000-07:00") + "'"
}

// Query executes SQL query on TDengine.
func (d *driver) Query(ctx context.Context, db, sqlStr string) (*tsdb.QueryResult, error) {
	rows, err := d.db.QueryContext(ctx, sqlStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return tsdb.ScanRows(rows)
}

// Close closes the TDengine database connection.
func (d *driver) Close() error {
	return d.db.Close()
}
