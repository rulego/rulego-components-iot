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

// Package tsdb provides unified data model and driver interface for time-series databases.
package tsdb

import (
	"context"
	"errors"
)

// ErrUnsupported indicates this driver does not support the operation (e.g. query-only library receives Query)
var ErrUnsupported = errors.New("operation not supported by this tsdb driver")

// SeriesPoint time-series data point, unified model across TSDBs.
// Corresponds to InfluxDB/OpenGemini measurement + tags + fields + timestamp,
// each driver encodes it to line protocol / SQL / native protocol.
//
// JSON input example: {"measurement":"device1","tags":{"site":"A"},"fields":{"temp":25.3},"timestamp":1721900000000000000}
type SeriesPoint struct {
	Measurement string                 `json:"measurement"` // Measurement table/device table name
	Tags        map[string]string      `json:"tags"`        // Index dimensions: deviceId/location/...
	Fields      map[string]interface{} `json:"fields"`      // Numerical/status values
	Timestamp   int64                  `json:"timestamp"`   // Nanosecond timestamp; 0 means driver uses current time when writing
}

// QueryResult general query result, organized by columns and rows
type QueryResult struct {
	Columns []string
	Rows    []map[string]interface{}
}

// Driver time-series database driver interface.
// db parameter is storage container identifier, each driver interprets it: OpenGemini=database, InfluxDB=bucket (bound at construction, WritePoints db parameter can be ignored),
// TDengine=db, TimescaleDB=schema, PromRemote unused.
type Driver interface {
	// WritePoints batch writes time-series points.
	WritePoints(ctx context.Context, db string, points []SeriesPoint) error
	// Query executes query; write-only libraries return ErrUnsupported. db semantics same as WritePoints (InfluxDB passes org here).
	Query(ctx context.Context, db, sql string) (*QueryResult, error)
	// Close releases connection.
	Close() error
}
