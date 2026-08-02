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

package influxdb

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
)

// TestE2E_InfluxDB real end-to-end: write SeriesPoint to InfluxDB 2.x, verify value with Flux query.
// Requires InfluxDB 2.x running first (test/e2e/docker-compose.yml or docker run -p 8086:8086 with DOCKER_INFLUXDB_INIT_* setup env),
// set E2E_INFLUXDB_URL=http://localhost:8086, E2E_INFLUXDB_TOKEN=<admin token> to enable; skip if not set.
// E2E_INFLUXDB_ORG (default rulego), E2E_INFLUXDB_BUCKET (default iot) are optional.
func TestE2E_InfluxDB(t *testing.T) {
	url := os.Getenv("E2E_INFLUXDB_URL")
	token := os.Getenv("E2E_INFLUXDB_TOKEN")
	if url == "" || token == "" {
		t.Skip("set E2E_INFLUXDB_URL and E2E_INFLUXDB_TOKEN to enable real e2e test")
	}
	org := os.Getenv("E2E_INFLUXDB_ORG")
	if org == "" {
		org = "rulego"
	}
	bucket := os.Getenv("E2E_INFLUXDB_BUCKET")
	if bucket == "" {
		bucket = "iot"
	}

	client := influxdb2.NewClient(url, token)
	d := newDriver(client, org, bucket)

	measurement := fmt.Sprintf("e2e_iot_%d", time.Now().UnixNano())
	ctx := context.Background()
	point := tsdb.SeriesPoint{
		Measurement: measurement,
		Tags:        map[string]string{"host": "e2e"},
		Fields:      map[string]interface{}{"value": 42.5},
		Timestamp:   time.Now().UnixNano(),
	}
	// When env vars are set, expect to run: wait for setup completion, retry same point idempotently, continuous failure treated as error
	if err := waitReady(60*time.Second, func() error {
		return d.WritePoints(ctx, bucket, []tsdb.SeriesPoint{point})
	}); err != nil {
		t.Fatalf("influxdb not ready within 60s: %v", err)
	}

	// Brief wait required before data becomes queryable after InfluxDB write
	time.Sleep(2 * time.Second)
	flux := fmt.Sprintf(
		`from(bucket:"%s") |> range(start: -5m) |> filter(fn:(r) => r._measurement == "%s") |> filter(fn:(r) => r._field == "value")`,
		bucket, measurement)
	res, err := d.Query(ctx, org, flux)
	assert.Nil(t, err)
	assert.True(t, len(res.Rows) > 0, "query should return the written point")
	assert.Equal(t, 42.5, res.Rows[0]["_value"])
	assert.Equal(t, "e2e", res.Rows[0]["host"])
}

// waitReady retries ready every 2s within timeout, returns last error if all attempts fail.
func waitReady(timeout time.Duration, ready func() error) error {
	var err error
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err = ready(); err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return err
}
