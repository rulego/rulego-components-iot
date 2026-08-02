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
	"github.com/stretchr/testify/require"
	_ "github.com/taosdata/driver-go/v3/taosRestful"
)

// TestE2E_TDengine real end-to-end: covers super table auto subtable creation, string escaping roundtrip, field superset NULL fill,
// large batch chunked writes, normal table without tags - five paths.
// Requires TDengine running first (docker run -p 6041:6041 tdengine/tdengine),
// set E2E_TDENGINE_DSN=root:taosdata@http(localhost:6041)/ to enable; skip if not set, fail if set but unreachable.
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
	// When env vars are set, expect to run: wait for service readiness, continuous unreachability treated as failure
	var dbErr error
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, dbErr = db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS iot_e2e"); dbErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if dbErr != nil {
		t.Fatalf("tdengine not reachable within 60s: %v", dbErr)
	}
	suffix := time.Now().UnixNano()
	now := time.Now().UnixNano()

	// Super table mode: value, host are reserved words, bare SQL requires backticks
	stable := fmt.Sprintf("e2e_st_%d", suffix)
	_, err = db.ExecContext(ctx, fmt.Sprintf(
		"CREATE STABLE iot_e2e.%s (ts TIMESTAMP, `value` DOUBLE, q DOUBLE, note NCHAR(64)) TAGS (`host` NCHAR(32))", stable))
	require.Nil(t, err, "create stable")
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf("DROP STABLE IF EXISTS iot_e2e.%s", stable)) }()

	const tricky = `C:\new 'q'`
	err = d.WritePoints(ctx, "iot_e2e", []tsdb.SeriesPoint{
		{Measurement: stable, Tags: map[string]string{"host": "e2e1"}, Fields: map[string]interface{}{"value": 42.5, "note": tricky}, Timestamp: now},
		{Measurement: stable, Tags: map[string]string{"host": "e2e2"}, Fields: map[string]interface{}{"value": 43.5}, Timestamp: now},
		{Measurement: stable, Tags: map[string]string{"host": "sup"}, Fields: map[string]interface{}{"value": 1.5}, Timestamp: now},
		{Measurement: stable, Tags: map[string]string{"host": "sup"}, Fields: map[string]interface{}{"q": 2.0, "value": 3.0}, Timestamp: now + int64(time.Second)},
	})
	require.Nil(t, err, "write to TDengine")

	res, err := d.Query(ctx, "iot_e2e", fmt.Sprintf("SELECT `host`, `value`, q, note FROM iot_e2e.%s ORDER BY `host`, ts", stable))
	require.Nil(t, err)
	require.Equal(t, 4, len(res.Rows))
	assert.Equal(t, "e2e1", res.Rows[0]["host"])
	assert.Equal(t, 42.5, res.Rows[0]["value"])
	assert.Equal(t, tricky, res.Rows[0]["note"], "backslash/single quote escaping roundtrip")
	assert.Equal(t, "e2e2", res.Rows[1]["host"])
	assert.Equal(t, "sup", res.Rows[2]["host"])
	assert.Equal(t, 1.5, res.Rows[2]["value"])
	assert.Nil(t, res.Rows[2]["q"], "field superset: missing columns filled with NULL")
	assert.Equal(t, "sup", res.Rows[3]["host"])
	assert.Equal(t, 3.0, res.Rows[3]["value"])
	assert.Equal(t, 2.0, res.Rows[3]["q"])

	// Large batch chunking: single subtable 8000 rows (~700KB, triggers multi-statement split)
	const chunkRows = 8000
	pts := make([]tsdb.SeriesPoint, 0, chunkRows)
	for i := 0; i < chunkRows; i++ {
		pts = append(pts, tsdb.SeriesPoint{
			Measurement: stable,
			Tags:        map[string]string{"host": "chunk"},
			Fields:      map[string]interface{}{"value": float64(i)},
			Timestamp:   now + int64(i)*int64(time.Millisecond),
		})
	}
	assert.Nil(t, d.WritePoints(ctx, "iot_e2e", pts), "chunked batch write")

	res, err = d.Query(ctx, "iot_e2e", fmt.Sprintf("SELECT COUNT(*) AS cnt FROM iot_e2e.%s WHERE `host` = 'chunk'", stable))
	require.Nil(t, err)
	require.Equal(t, 1, len(res.Rows))
	assert.EqualValues(t, chunkRows, res.Rows[0]["cnt"])

	// Normal table mode: without tags writes to pre-created normal table of same name
	normal := fmt.Sprintf("e2e_normal_%d", suffix)
	_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE TABLE iot_e2e.%s (ts TIMESTAMP, `value` DOUBLE)", normal))
	assert.Nil(t, err, "create normal table")
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS iot_e2e.%s", normal)) }()

	err = d.WritePoints(ctx, "iot_e2e", []tsdb.SeriesPoint{
		{Measurement: normal, Fields: map[string]interface{}{"value": 7.25}, Timestamp: now},
	})
	assert.Nil(t, err, "write to normal table")

	res, err = d.Query(ctx, "iot_e2e", fmt.Sprintf("SELECT `value` FROM iot_e2e.%s", normal))
	require.Nil(t, err)
	require.Equal(t, 1, len(res.Rows))
	assert.Equal(t, 7.25, res.Rows[0]["value"])
}
