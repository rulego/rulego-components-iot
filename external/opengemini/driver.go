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

// Package opengemini provides OpenGemini time-series database write (WriteNode) and query (QueryNode) nodes,
// and adapts to pkg/tsdb.Driver via driver.
package opengemini

import (
	"context"
	"errors"
	"time"

	"github.com/openGemini/opengemini-client-go/opengemini"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
)

// driver adapts tsdb.SeriesPoint to OpenGemini client.
type driver struct {
	client opengemini.Client
}

var _ tsdb.Driver = (*driver)(nil)

// NewDriver creates a new OpenGemini tsdb.Driver
func NewDriver(client opengemini.Client) *driver {
	return &driver{client: client}
}

// newDriver is for internal backward compatibility
func newDriver(client opengemini.Client) *driver {
	return &driver{client: client}
}

// WritePoints maps SeriesPoint to OpenGemini Point and batch writes.
func (d *driver) WritePoints(ctx context.Context, db string, points []tsdb.SeriesPoint) error {
	ops := make([]*opengemini.Point, 0, len(points))
	for i := range points {
		if points[i].Measurement == "" {
			continue
		}
		fields := make(map[string]interface{}, len(points[i].Fields))
		for k, v := range points[i].Fields {
			if tsdb.ValidFieldValue(v) {
				fields[k] = v
			}
		}
		if len(fields) == 0 {
			continue
		}
		ts := points[i].Timestamp
		if ts == 0 {
			ts = time.Now().UnixNano()
		}
		ops = append(ops, &opengemini.Point{
			Measurement: points[i].Measurement,
			Tags:        points[i].Tags,
			Fields:      fields,
			Timestamp:   ts,
			Precision:   opengemini.PrecisionNanosecond,
		})
	}
	return d.client.WriteBatchPoints(ctx, db, ops)
}

// Query executes SQL, results organized as generic QueryResult (columns + rows).
func (d *driver) Query(ctx context.Context, db, sql string) (*tsdb.QueryResult, error) {
	res, err := d.client.Query(opengemini.Query{Database: db, Command: sql})
	if err != nil {
		return nil, err
	}
	if err = hasError(res); err != nil {
		return nil, err
	}
	return toQueryResult(res), nil
}

// Close closes underlying client.
func (d *driver) Close() error {
	return d.client.Close()
}

// hasError checks error information in query result.
func hasError(result *opengemini.QueryResult) error {
	if result == nil {
		return nil
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	for _, r := range result.Results {
		if r != nil && r.Error != "" {
			return errors.New(r.Error)
		}
	}
	return nil
}

// toQueryResult converts OpenGemini query result to generic QueryResult (columns + rows).
func toQueryResult(result *opengemini.QueryResult) *tsdb.QueryResult {
	out := &tsdb.QueryResult{Columns: []string{}, Rows: []map[string]interface{}{}}
	if result == nil {
		return out
	}
	for _, r := range result.Results {
		if r == nil {
			continue
		}
		for _, s := range r.Series {
			if s == nil || len(s.Columns) == 0 {
				continue
			}
			if len(out.Columns) == 0 {
				out.Columns = append(out.Columns, s.Columns...)
			}
			for _, val := range s.Values {
				row := make(map[string]interface{}, len(s.Columns))
				for i, col := range s.Columns {
					if i < len(val) {
						row[col] = val[i]
					}
				}
				out.Rows = append(out.Rows, row)
			}
		}
	}
	return out
}
