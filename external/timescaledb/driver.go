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

// buildInsertSQL builds INSERT SQL for a single SeriesPoint.
func buildInsertSQL(db string, point tsdb.SeriesPoint) string {
	var columns []string
	var values []string

	// Add tags as columns
	for k, v := range point.Tags {
		columns = append(columns, quoteIdentifier(k))
		values = append(values, formatValue(v))
	}

	// Add fields as columns
	for k, v := range point.Fields {
		columns = append(columns, quoteIdentifier(k))
		values = append(values, formatValue(v))
	}

	// Add timestamp: nanoseconds -> PostgreSQL timestamp
	columns = append(columns, quoteIdentifier("time"))
	if point.Timestamp == 0 {
		values = append(values, "NOW()")
	} else {
		values = append(values, fmt.Sprintf("to_timestamp(%d/1000000000.0)", point.Timestamp))
	}

	return fmt.Sprintf("INSERT INTO %s.%s (%s) VALUES (%s)",
		quoteIdentifier(db),
		quoteIdentifier(point.Measurement),
		strings.Join(columns, ","),
		strings.Join(values, ","),
	)
}

// WritePoints writes SeriesPoints to TimescaleDB using SQL INSERT.
func (d *driver) WritePoints(ctx context.Context, db string, points []tsdb.SeriesPoint) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
		}
	}()

	for _, point := range points {
		sqlStr := buildInsertSQL(db, point)
		_, err := tx.ExecContext(ctx, sqlStr)
		if err != nil {
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
