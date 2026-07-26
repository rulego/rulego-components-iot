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

package tdengine

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
	_ "github.com/taosdata/driver-go/v3/taosRestful"
)

// TestE2E_TDengine 真实端到端：写 SeriesPoint 到 TDengine，SQL 查询验证值。
// 需先起 TDengine（test/e2e/docker-compose.yml 或 docker run -p 6041:6041 tdengine/tdengine），
// 设 E2E_TDENGINE_DSN=root:taosdata@http(localhost:6041)/ 启用；未设则 skip。
func TestE2E_TDengine(t *testing.T) {
	dsn := os.Getenv("E2E_TDENGINE_DSN")
	if dsn == "" {
		t.Skip("set E2E_TDENGINE_DSN (e.g. root:taosdata@http(localhost:6041)/) to enable real e2e test")
	}
	db, err := sql.Open("taosRestful", dsn)
	assert.Nil(t, err)
	d := newDriver(db)
	defer d.Close()

	ctx := context.Background()
	if _, err = db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS iot_e2e"); err != nil {
		t.Skipf("create database failed (tdengine not ready?): %v", err)
	}
	measurement := fmt.Sprintf("e2e_iot_%d", time.Now().UnixNano())
	_, err = db.ExecContext(ctx, fmt.Sprintf(
		"CREATE TABLE iot_e2e.%s (ts TIMESTAMP, host NCHAR(32), value DOUBLE)", measurement))
	assert.Nil(t, err, "create table")
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf("DROP TABLE iot_e2e.%s", measurement)) }()

	err = d.WritePoints(ctx, "iot_e2e", []tsdb.SeriesPoint{{
		Measurement: measurement,
		Tags:        map[string]string{"host": "e2e"},
		Fields:      map[string]interface{}{"value": 42.5},
		Timestamp:   time.Now().UnixNano(),
	}})
	assert.Nil(t, err, "write to TDengine")

	res, err := d.Query(ctx, "iot_e2e", fmt.Sprintf("SELECT host, value FROM iot_e2e.%s", measurement))
	assert.Nil(t, err)
	assert.Equal(t, 1, len(res.Rows))
	assert.Equal(t, "e2e", res.Rows[0]["host"])
	assert.Equal(t, 42.5, res.Rows[0]["value"])
}
