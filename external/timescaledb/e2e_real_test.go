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

package timescaledb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
)

// TestE2E_TimescaleDB 真实端到端：写 SeriesPoint 到 TimescaleDB，SQL 查询验证值。
// 需先起 TimescaleDB（test/e2e/docker-compose.yml 或 docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres timescale/timescaledb:latest-pg16），
// 设 E2E_TIMESCALEDB_DSN=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable 启用；未设则 skip。
func TestE2E_TimescaleDB(t *testing.T) {
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if dsn == "" {
		t.Skip("set E2E_TIMESCALEDB_DSN to enable real e2e test")
	}
	db, err := sql.Open("postgres", dsn)
	assert.Nil(t, err)
	d := newDriver(db)
	defer d.Close()

	ctx := context.Background()
	measurement := fmt.Sprintf("e2e_iot_%d", time.Now().UnixNano())
	_, err = db.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, value double precision)`, measurement))
	if err != nil {
		t.Skipf("create table failed (db not ready?): %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf(`DROP TABLE public.%s`, measurement)) }()

	err = d.WritePoints(ctx, "public", []tsdb.SeriesPoint{{
		Measurement: measurement,
		Tags:        map[string]string{"host": "e2e"},
		Fields:      map[string]interface{}{"value": 42.5},
		Timestamp:   time.Now().UnixNano(),
	}})
	assert.Nil(t, err, "write to TimescaleDB")

	res, err := d.Query(ctx, "public", fmt.Sprintf(`SELECT host, value FROM public.%s`, measurement))
	assert.Nil(t, err)
	assert.Equal(t, 1, len(res.Rows))
	assert.Equal(t, "e2e", res.Rows[0]["host"])
	assert.Equal(t, 42.5, res.Rows[0]["value"])
}
