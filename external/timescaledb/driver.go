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

// The following two functions bind PostgreSQL dialect parameters (double quote identifiers, standard string escaping) to pkg/tsdb common implementation.

func quoteIdentifier(s string) string { return tsdb.QuoteIdentifier(s, '"') }

func formatValue(v interface{}) string { return tsdb.FormatValue(v, false) }

func validFieldValue(v interface{}) bool { return tsdb.ValidFieldValue(v) }

// maxStatementBytes is the byte budget for a single INSERT statement.
const maxStatementBytes = 1024 * 1024

const insertPrefix = "INSERT INTO "

// reservedColumn is the business column name that conflicts with hardcoded time column, excluded to avoid duplication.
const reservedColumn = "time"

// rowGroup is a group of points from same measurement (tags and fields both as normal columns).
type rowGroup struct {
	measurement string
	colSet      map[string]struct{}
	rows        []groupRow
}

// groupRow is a single row: column values (tag as string, field as any) and timestamp.
type groupRow struct {
	ts     int64
	values map[string]interface{}
}

// buildInsertStatements assembles multi-VALUES INSERT by measurement grouping, splits statements by byte budget.
// PostgreSQL single INSERT can only target one table, so different measurements are not merged into same statement.
// Returns nil when no writable points (empty input or all with no valid columns).
func buildInsertStatements(db string, points []tsdb.SeriesPoint) []string {
	groups := make(map[string]*rowGroup)
	var order []string
	for i := range points {
		p := points[i]
		if p.Measurement == "" {
			continue
		}
		// First collect writable columns (exclude reserved names and invalid values), skip if no writable columns and do not create group
		row := groupRow{ts: p.Timestamp, values: make(map[string]interface{}, len(p.Tags)+len(p.Fields))}
		for k, v := range p.Tags {
			if k == reservedColumn {
				continue
			}
			row.values[k] = v
		}
		for k, v := range p.Fields {
			if k == reservedColumn || !validFieldValue(v) {
				continue
			}
			row.values[k] = v
		}
		if len(row.values) == 0 {
			continue
		}
		g, exists := groups[p.Measurement]
		if !exists {
			g = &rowGroup{measurement: p.Measurement, colSet: make(map[string]struct{})}
			groups[p.Measurement] = g
			order = append(order, p.Measurement)
		}
		for k := range row.values {
			g.colSet[k] = struct{}{}
		}
		g.rows = append(g.rows, row)
	}

	// Each group becomes separate statement (PG single table limit), same group multi-rowmerged into multi VALUES, split when over budget.
	var stmts []string
	for _, m := range order {
		for _, seg := range groupSegments(db, groups[m]) {
			stmts = append(stmts, insertPrefix+seg)
		}
	}
	return stmts
}

// groupSegments renders a group into multiple table segments: column header appears once followed by multiple row VALUES, missing columns filled with NULL.
// When single group exceeds maxStatementBytes, break and start new segment (repeat column header).
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

// tableHeader renders column header: schema.measurement (business columns...,time) VALUES.
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

// renderRow renders single row VALUES: business column values first, timestamp last, missing columns filled with NULL.
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

// formatTimestamp formats nanosecond timestamp; 0 returns NOW().
func formatTimestamp(ts int64) string {
	if ts == 0 {
		return "NOW()"
	}
	return fmt.Sprintf("to_timestamp(%d/1000000000.0)", ts)
}

// sortedSetKeys returns sorted slice of set keys, ensures deterministic column order.
func sortedSetKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// WritePoints batch writes: assemble multi-VALUES INSERT, execute each statement in single transaction, rollback on any failure.
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
