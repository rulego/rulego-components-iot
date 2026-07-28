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

// TestE2E_TDengine 真实端到端：覆盖超级表自动建子表、字符串转义往返、字段超集补 NULL、
// 大批量分片写入、无 tags 普通表五条路径。
// 需先起 TDengine（docker run -p 6041:6041 tdengine/tdengine），
// 设 E2E_TDENGINE_DSN=root:taosdata@http(localhost:6041)/ 启用；未设则 skip，设了连不上则 fail。
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
	// 环境变量已设即期望可跑：等待服务就绪，持续不可达按失败处理
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

	// 超级表模式：value、host 是保留字，裸 SQL 须反引号
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
	assert.Equal(t, tricky, res.Rows[0]["note"], "反斜杠/单引号转义往返")
	assert.Equal(t, "e2e2", res.Rows[1]["host"])
	assert.Equal(t, "sup", res.Rows[2]["host"])
	assert.Equal(t, 1.5, res.Rows[2]["value"])
	assert.Nil(t, res.Rows[2]["q"], "字段超集：缺失列补 NULL")
	assert.Equal(t, "sup", res.Rows[3]["host"])
	assert.Equal(t, 3.0, res.Rows[3]["value"])
	assert.Equal(t, 2.0, res.Rows[3]["q"])

	// 大批量分片：单子表 8000 行（约 700KB，触发多语句拆分）
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

	// 普通表模式：无 tags 时写入同名预建普通表
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
