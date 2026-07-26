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

// TestE2E_InfluxDB 真实端到端：写 SeriesPoint 到 InfluxDB 2.x，Flux 查询验证值。
// 需先起 InfluxDB 2.x（test/e2e/docker-compose.yml 或 docker run -p 8086:8086 带 DOCKER_INFLUXDB_INIT_* setup 环境），
// 设 E2E_INFLUXDB_URL=http://localhost:8086、E2E_INFLUXDB_TOKEN=<admin token> 启用；未设则 skip。
// E2E_INFLUXDB_ORG(默认 rulego)、E2E_INFLUXDB_BUCKET(默认 iot) 可选。
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
	err := d.WritePoints(ctx, bucket, []tsdb.SeriesPoint{{
		Measurement: measurement,
		Tags:        map[string]string{"host": "e2e"},
		Fields:      map[string]interface{}{"value": 42.5},
		Timestamp:   time.Now().UnixNano(),
	}})
	assert.Nil(t, err, "write to InfluxDB")

	// InfluxDB 写入后可查需短暂等待
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
