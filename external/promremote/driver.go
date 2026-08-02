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

// Package promremote provides Prometheus Remote Write, VictoriaMetrics, and QuestDB support.
package promremote

import (
	"context"
	"fmt"
	"time"

	"github.com/castai/promwrite"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
)

// driver adapts tsdb.SeriesPoint to Prometheus Remote Write format.
type driver struct {
	client *promwrite.Client
	logger types.Logger
}

var _ tsdb.Driver = (*driver)(nil)

// NewDriver creates a new PromRemote driver.
func NewDriver(client *promwrite.Client, logger types.Logger) *driver {
	if logger == nil {
		logger = types.DefaultLogger()
	}
	return &driver{client: client, logger: logger}
}

// newDriver is for internal use.
func newDriver(client *promwrite.Client, logger types.Logger) *driver {
	return NewDriver(client, logger)
}

// WritePoints writes SeriesPoint to Prometheus Remote Write endpoint.
func (d *driver) WritePoints(ctx context.Context, db string, points []tsdb.SeriesPoint) error {
	var promPoints []promwrite.TimeSeries
	totalFields := 0

	for _, p := range points {
		if p.Measurement == "" {
			continue
		}
		labels := []promwrite.Label{{Name: "__name__", Value: p.Measurement}}
		for k, v := range p.Tags {
			labels = append(labels, promwrite.Label{Name: k, Value: v})
		}

		timestamp := p.Timestamp
		if timestamp == 0 {
			timestamp = time.Now().UnixNano()
		}

		for k, v := range p.Fields {
			if !tsdb.ValidFieldValue(v) {
				d.logger.Printf("[promremote] skip non-numeric field %q (value %v) in measurement %q", k, v, p.Measurement)
				continue
			}
			totalFields++
			// For each field, create a separate time series with field name as __name__ suffix
			fieldLabels := make([]promwrite.Label, len(labels))
			copy(fieldLabels, labels)
			// If there are multiple fields, we'll suffix the measurement name with field name
			if len(p.Fields) > 1 {
				fieldLabels[0] = promwrite.Label{Name: "__name__", Value: p.Measurement + "_" + k}
			}

			// Parse value as float64
			var floatVal float64
			switch val := v.(type) {
			case float64:
				floatVal = val
			case float32:
				floatVal = float64(val)
			case int:
				floatVal = float64(val)
			case int64:
				floatVal = float64(val)
			case int32:
				floatVal = float64(val)
			case uint:
				floatVal = float64(val)
			case uint64:
				floatVal = float64(val)
			case uint32:
				floatVal = float64(val)
			case int16:
				floatVal = float64(val)
			case uint16:
				floatVal = float64(val)
			case int8:
				floatVal = float64(val)
			case uint8:
				floatVal = float64(val)
			case bool:
				if val {
					floatVal = 1
				} else {
					floatVal = 0
				}
			default:
				d.logger.Printf("[promremote] skip non-numeric field %q (value %v) in measurement %q", k, v, p.Measurement)
				continue
			}

			promPoints = append(promPoints, promwrite.TimeSeries{
				Labels: fieldLabels,
				Sample: promwrite.Sample{
					Time:  time.Unix(0, timestamp),
					Value: floatVal,
				},
			})
		}
	}

	if len(promPoints) == 0 {
		// Has fields but all non-numeric and skipped: return error to avoid silent data loss
		if totalFields > 0 {
			return fmt.Errorf("promremote: all %d field(s) non-numeric, nothing written", totalFields)
		}
		return nil
	}

	_, err := d.client.Write(ctx, &promwrite.WriteRequest{
		TimeSeries: promPoints,
	})
	return err
}

// Query implements tsdb.Driver. PromRemote doesn't support querying.
func (d *driver) Query(ctx context.Context, db, query string) (*tsdb.QueryResult, error) {
	return nil, tsdb.ErrUnsupported
}

// Close implements tsdb.Driver.
func (d *driver) Close() error {
	return nil
}
