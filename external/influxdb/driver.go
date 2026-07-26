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

// Package influxdb provides InfluxDB time-series database write and query nodes,
// with driver adapter to pkg/tsdb.Driver.
package influxdb

import (
	"context"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
)

// driver adapts tsdb.SeriesPoint to InfluxDB client.
type driver struct {
	writeAPI api.WriteAPIBlocking
	queryAPI api.QueryAPI
}

var _ tsdb.Driver = (*driver)(nil)

// NewDriver creates a new InfluxDB tsdb.Driver
func NewDriver(client influxdb2.Client, org, bucket string) *driver {
	return &driver{
		writeAPI: client.WriteAPIBlocking(org, bucket),
		queryAPI: client.QueryAPI(org),
	}
}

// newDriver is for internal backward compatibility
func newDriver(client influxdb2.Client, org, bucket string) *driver {
	return &driver{
		writeAPI: client.WriteAPIBlocking(org, bucket),
		queryAPI: client.QueryAPI(org),
	}
}

// WritePoints maps SeriesPoint to InfluxDB Point and writes in batch.
func (d *driver) WritePoints(ctx context.Context, bucket string, points []tsdb.SeriesPoint) error {
	pts := make([]*write.Point, 0, len(points))
	for i := range points {
		ts := points[i].Timestamp
		if ts == 0 {
			ts = time.Now().UnixNano()
		}
		pts = append(pts, influxdb2.NewPoint(
			points[i].Measurement,
			points[i].Tags,
			points[i].Fields,
			time.Unix(0, ts),
		))
	}
	if len(pts) == 0 {
		return nil
	}
	return d.writeAPI.WritePoint(ctx, pts...)
}

// Query executes Flux query, results organized as generic QueryResult (columns + rows).
func (d *driver) Query(ctx context.Context, org, flux string) (*tsdb.QueryResult, error) {
	result, err := d.queryAPI.Query(ctx, flux)
	if err != nil {
		return nil, err
	}
	return toQueryResult(result), nil
}

// Close closes underlying client.
func (d *driver) Close() error {
	return nil
}

// toQueryResult converts InfluxDB query result to generic QueryResult (columns + rows).
func toQueryResult(result *api.QueryTableResult) *tsdb.QueryResult {
	out := &tsdb.QueryResult{}
	if result == nil {
		return out
	}
	columnsSet := false
	for result.Next() {
		record := result.Record()
		row := make(map[string]interface{})
		for k, v := range record.Values() {
			row[k] = v
		}
		if !columnsSet {
			for k := range row {
				out.Columns = append(out.Columns, k)
			}
			columnsSet = true
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}
