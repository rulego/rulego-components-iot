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

package tsdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	_ "github.com/lib/pq"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/taosdata/driver-go/v3/taosRestful"
)

// chainPoints acquisition point array: temperature/humidity will be mapped, pressure unmapped should be filtered out.
func chainPoints() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf(
		`[{"name":"temperature","value":25.3,"timestamp":%d},{"name":"humidity","value":60,"timestamp":%d},{"name":"pressure","value":101,"timestamp":%d}]`,
		now, now, now)
}

// mappingConfig acquisition data mapping: measurement + host tag + fields filtering/renaming.
func mappingConfig(measurement string) map[string]interface{} {
	return map[string]interface{}{
		"measurement": measurement,
		"tags":        []map[string]interface{}{{"key": "host", "value": "e2e"}},
		"fields": []map[string]interface{}{
			{"key": "temp_c", "source": "temperature"},
			{"key": "humi_pct", "source": "humidity"},
		},
	}
}

// runWriteChain builds single node x/tsdbWrite rule chain and sends acquisition point array, waits for completion synchronously.
func runWriteChain(t *testing.T, chainID string, config map[string]interface{}) {
	t.Helper()
	dsl := map[string]interface{}{
		"ruleChain": map[string]interface{}{"id": chainID, "root": true},
		"metadata": map[string]interface{}{
			"firstNodeIndex": 0,
			"nodes": []map[string]interface{}{
				{"id": "w", "type": "x/tsdbWrite", "configuration": config},
			},
		},
	}
	b, err := json.Marshal(dsl)
	assert.Nil(t, err)
	rg, err := rulego.New(chainID, b)
	assert.Nil(t, err, "create rule engine")
	defer rulego.Del(chainID)

	msg := types.NewMsg(0, "WRITE", types.JSON, types.NewMetadata(), chainPoints())
	rg.OnMsgAndWait(msg)
}

// TestE2EChain_InfluxDB acquisition point array -> x/tsdbWrite(influxdb) -> Flux query read back.
func TestE2EChain_InfluxDB(t *testing.T) {
	url := os.Getenv("E2E_INFLUXDB_URL")
	token := os.Getenv("E2E_INFLUXDB_TOKEN")
	if url == "" || token == "" {
		t.Skip("set E2E_INFLUXDB_URL and E2E_INFLUXDB_TOKEN to enable real chain e2e")
	}
	org := os.Getenv("E2E_INFLUXDB_ORG")
	if org == "" {
		org = "rulego"
	}
	bucket := os.Getenv("E2E_INFLUXDB_BUCKET")
	if bucket == "" {
		bucket = "iot"
	}
	m := fmt.Sprintf("e2e_chain_%d", time.Now().UnixNano())

	config := mappingConfig(m)
	config["driver"] = "influxdb"
	config["url"] = url
	config["token"] = token
	config["org"] = org
	config["bucket"] = bucket
	runWriteChain(t, "e2e_chain_influx", config)

	time.Sleep(2 * time.Second)
	client := influxdb2.NewClient(url, token)
	defer client.Close()
	res, err := client.QueryAPI(org).Query(context.Background(),
		fmt.Sprintf(`from(bucket:"%s") |> range(start:-5m) |> filter(fn:(r)=>r._measurement=="%s")`, bucket, m))
	assert.Nil(t, err)
	got := map[string]bool{}
	for res.Next() {
		if f, ok := res.Record().Values()["_field"].(string); ok {
			got[f] = true
		}
	}
	assert.True(t, got["temp_c"], "mapped field temp_c should be written")
	assert.True(t, got["humi_pct"], "mapped field humi_pct should be written")
	assert.False(t, got["pressure"], "unmapped point pressure should be filtered")
	assert.False(t, got["temperature"], "source name should be renamed, not written as-is")
}

// TestE2EChain_TimescaleDB acquisition point array -> x/tsdbWrite(timescaledb) -> SQL query read back.
func TestE2EChain_TimescaleDB(t *testing.T) {
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if dsn == "" {
		t.Skip("set E2E_TIMESCALEDB_DSN to enable real chain e2e")
	}
	db, err := sql.Open("postgres", dsn)
	assert.Nil(t, err)
	defer db.Close()
	ctx := context.Background()
	m := fmt.Sprintf("e2e_chain_%d", time.Now().UnixNano())
	createSQL := fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, temp_c double precision, humi_pct double precision)`, m)
	if err := waitReady(60*time.Second, func() error {
		_, e := db.ExecContext(ctx, createSQL)
		return e
	}); err != nil {
		t.Fatalf("timescaledb not ready within 60s: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf(`DROP TABLE public.%s`, m)) }()

	config := mappingConfig(m)
	config["driver"] = "timescaledb"
	config["dsn"] = dsn
	config["db"] = "public"
	runWriteChain(t, "e2e_chain_timescale", config)

	var host string
	var tempC, humiPct float64
	row := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT host, temp_c, humi_pct FROM public.%s`, m))
	assert.Nil(t, row.Scan(&host, &tempC, &humiPct))
	assert.Equal(t, "e2e", host)
	assert.Equal(t, 25.3, tempC)
	assert.Equal(t, float64(60), humiPct)
}

// TestE2EChain_TDengine acquisition point array -> x/tsdbWrite(tdengine) -> SQL query read back.
func TestE2EChain_TDengine(t *testing.T) {
	dsn := os.Getenv("E2E_TDENGINE_DSN")
	if dsn == "" {
		t.Skip("set E2E_TDENGINE_DSN to enable real chain e2e")
	}
	db, err := sql.Open("taosRestful", dsn)
	assert.Nil(t, err)
	defer db.Close()
	ctx := context.Background()
	if err := waitReady(60*time.Second, func() error {
		_, e := db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS iot_e2e")
		return e
	}); err != nil {
		t.Fatalf("tdengine not reachable within 60s: %v", err)
	}
	// Mapping config with tags, pre-built per super table model (host is reserved word, requires backticks)
	m := fmt.Sprintf("e2e_chain_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, fmt.Sprintf(
		"CREATE STABLE iot_e2e.%s (ts TIMESTAMP, temp_c DOUBLE, humi_pct DOUBLE) TAGS (`host` NCHAR(32))", m)); err != nil {
		t.Fatalf("create stable failed: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf("DROP STABLE IF EXISTS iot_e2e.%s", m)) }()

	config := mappingConfig(m)
	config["driver"] = "tdengine"
	config["dsn"] = dsn
	config["db"] = "iot_e2e"
	runWriteChain(t, "e2e_chain_tdengine", config)

	var host string
	var tempC, humiPct float64
	row := db.QueryRowContext(ctx, fmt.Sprintf("SELECT `host`, temp_c, humi_pct FROM iot_e2e.%s", m))
	assert.Nil(t, row.Scan(&host, &tempC, &humiPct))
	assert.Equal(t, "e2e", host)
	assert.Equal(t, 25.3, tempC)
	assert.Equal(t, float64(60), humiPct)
}

// TestE2EChain_PromRemote acquisition point array -> x/tsdbWrite(promremote) -> VictoriaMetrics query read back.
func TestE2EChain_PromRemote(t *testing.T) {
	vm := os.Getenv("E2E_VICTORIAMETRICS_URL")
	if vm == "" {
		t.Skip("set E2E_VICTORIAMETRICS_URL to enable real chain e2e")
	}
	m := fmt.Sprintf("e2e_chain_%d", time.Now().UnixNano())

	config := mappingConfig(m)
	config["driver"] = "promremote"
	config["url"] = vm + "/api/v1/write"
	runWriteChain(t, "e2e_chain_prom", config)

	// When multiple fields, promremote concatenates metric name as measurement_field; VM new series index has delay, poll until queryable
	require.Eventually(t, func() bool { return vmHasSeries(t, vm, m+"_temp_c") },
		120*time.Second, 5*time.Second, "mapped metric %s_temp_c should exist", m)
	require.Eventually(t, func() bool { return vmHasSeries(t, vm, m+"_humi_pct") },
		120*time.Second, 5*time.Second, "mapped metric %s_humi_pct should exist", m)
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

// vmHasSeries queries whether VictoriaMetrics series exists.
func vmHasSeries(t *testing.T, vm, metric string) bool {
	t.Helper()
	now := time.Now().Unix()
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/query_range?query=%s&start=%d&end=%d&step=15", vm, metric, now-300, now+60))
	if err != nil {
		t.Logf("vm query %s error: %v", metric, err)
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Data struct {
			Result []interface{} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return false
	}
	return len(out.Data.Result) > 0
}

const (
	concurrentWorkers   = 8
	concurrentMsgsPerW  = 25
	concurrentTotalRows = concurrentWorkers * concurrentMsgsPerW
)

// stressPoints generates acquisition point array, timestamp increments by millisecond per global sequence (same table same timestamp is overwrite semantics).
func stressPoints(seq int64, baseNs int64) string {
	ts := baseNs + seq*int64(time.Millisecond)
	return fmt.Sprintf(
		`[{"name":"temperature","value":25.3,"timestamp":%d},{"name":"humidity","value":60,"timestamp":%d},{"name":"pressure","value":101,"timestamp":%d}]`,
		ts, ts, ts)
}

// runConcurrentWrite multiple goroutines concurrently send messages to single node x/tsdbWrite chain, counts success/failure.
func runConcurrentWrite(t *testing.T, chainID string, config map[string]interface{}) (ok, fail int64) {
	t.Helper()
	dsl := map[string]interface{}{
		"ruleChain": map[string]interface{}{"id": chainID, "root": true},
		"metadata": map[string]interface{}{
			"firstNodeIndex": 0,
			"nodes": []map[string]interface{}{
				{"id": "w", "type": "x/tsdbWrite", "configuration": config},
			},
		},
	}
	b, err := json.Marshal(dsl)
	require.Nil(t, err)
	rg, err := rulego.New(chainID, b)
	require.Nil(t, err, "create rule engine")
	defer rulego.Del(chainID)

	baseNs := time.Now().UnixNano()
	var seq int64
	var wg sync.WaitGroup
	for g := 0; g < concurrentWorkers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < concurrentMsgsPerW; i++ {
				var done sync.WaitGroup
				done.Add(1)
				msg := types.NewMsg(0, "W", types.JSON, types.NewMetadata(), stressPoints(atomic.AddInt64(&seq, 1), baseNs))
				rg.OnMsg(msg, types.WithOnEnd(func(ctx types.RuleContext, m types.RuleMsg, err error, relationType string) {
					if relationType == types.Success {
						atomic.AddInt64(&ok, 1)
					} else {
						atomic.AddInt64(&fail, 1)
					}
					done.Done()
				}))
				done.Wait()
			}
		}()
	}
	wg.Wait()
	return ok, fail
}

// TestConcurrent_TSDBWrite_TDengine 8 concurrent ×25 messages write to same super table subtable, exact row count verification.
func TestConcurrent_TSDBWrite_TDengine(t *testing.T) {
	dsn := os.Getenv("E2E_TDENGINE_DSN")
	if dsn == "" {
		t.Skip("set E2E_TDENGINE_DSN to enable concurrent test")
	}
	db, m := setupTDengineStable(t, dsn)
	defer dropTDengineStable(db, m)

	config := mappingConfig(m)
	config["driver"] = "tdengine"
	config["dsn"] = dsn
	config["db"] = "iot_e2e"
	ok, fail := runConcurrentWrite(t, "e2e_conc_tdengine", config)
	require.Zero(t, fail, "all messages should succeed")
	require.EqualValues(t, concurrentTotalRows, ok)
	assertTDengineCount(t, db, m, concurrentTotalRows)
}

// TestConcurrent_TSDBWrite_TimescaleDB 8 concurrent ×25 messages write to same normal table, exact row count verification.
func TestConcurrent_TSDBWrite_TimescaleDB(t *testing.T) {
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if dsn == "" {
		t.Skip("set E2E_TIMESCALEDB_DSN to enable concurrent test")
	}
	db, m := setupTimescaleTable(t, dsn)
	defer func() { _, _ = db.Exec(fmt.Sprintf(`DROP TABLE public.%s`, m)) }()

	config := mappingConfig(m)
	config["driver"] = "timescaledb"
	config["dsn"] = dsn
	config["db"] = "public"
	ok, fail := runConcurrentWrite(t, "e2e_conc_timescale", config)
	require.Zero(t, fail, "all messages should succeed")
	require.EqualValues(t, concurrentTotalRows, ok)
	var count int
	require.Nil(t, db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM public.%s`, m)).Scan(&count))
	require.Equal(t, concurrentTotalRows, count)
}

// TestConcurrent_TSDBWrite_InfluxDB 8 concurrent ×25 messages, only verify all succeed.
func TestConcurrent_TSDBWrite_InfluxDB(t *testing.T) {
	url := os.Getenv("E2E_INFLUXDB_URL")
	token := os.Getenv("E2E_INFLUXDB_TOKEN")
	if url == "" || token == "" {
		t.Skip("set E2E_INFLUXDB_URL and E2E_INFLUXDB_TOKEN to enable concurrent test")
	}
	config := mappingConfig(fmt.Sprintf("e2e_conc_%d", uniqueSuffix()))
	config["driver"] = "influxdb"
	config["url"] = url
	config["token"] = token
	config["org"] = envOr("E2E_INFLUXDB_ORG", "rulego")
	config["bucket"] = envOr("E2E_INFLUXDB_BUCKET", "iot")
	ok, fail := runConcurrentWrite(t, "e2e_conc_influx", config)
	require.Zero(t, fail, "all messages should succeed")
	require.EqualValues(t, concurrentTotalRows, ok)
}

// TestConcurrent_TSDBWrite_OpenGemini 8 concurrent ×25 messages, only verify all succeed.
func TestConcurrent_TSDBWrite_OpenGemini(t *testing.T) {
	addr := os.Getenv("E2E_OPENGEMINI_ADDR")
	if addr == "" {
		t.Skip("set E2E_OPENGEMINI_ADDR to enable concurrent test")
	}
	m := fmt.Sprintf("e2e_conc_%d", uniqueSuffix())
	config := mappingConfig(m)
	config["driver"] = "opengemini"
	config["server"] = addr
	config["database"] = "e2e_iot"
	ok, fail := runConcurrentWrite(t, "e2e_conc_opengemini", config)
	require.Zero(t, fail, "all messages should succeed")
	require.EqualValues(t, concurrentTotalRows, ok)
}

// TestConcurrent_TSDBWrite_PromRemote 8 concurrent ×25 messages, only verify all succeed.
func TestConcurrent_TSDBWrite_PromRemote(t *testing.T) {
	vm := os.Getenv("E2E_VICTORIAMETRICS_URL")
	if vm == "" {
		t.Skip("set E2E_VICTORIAMETRICS_URL to enable concurrent test")
	}
	config := mappingConfig(fmt.Sprintf("e2e_conc_%d", uniqueSuffix()))
	config["driver"] = "promremote"
	config["url"] = vm + "/api/v1/write"
	ok, fail := runConcurrentWrite(t, "e2e_conc_prom", config)
	require.Zero(t, fail, "all messages should succeed")
	require.EqualValues(t, concurrentTotalRows, ok)
}

func uniqueSuffix() int64 { return time.Now().UnixNano() }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func setupTDengineStable(t *testing.T, dsn string) (*sql.DB, string) {
	db, err := sql.Open("taosRestful", dsn)
	require.Nil(t, err)
	m := fmt.Sprintf("e2e_conc_%d", uniqueSuffix())
	_, err = db.Exec(fmt.Sprintf(
		"CREATE STABLE iot_e2e.%s (ts TIMESTAMP, temp_c DOUBLE, humi_pct DOUBLE) TAGS (`host` NCHAR(32))", m))
	require.Nil(t, err, "create stable")
	return db, m
}

func dropTDengineStable(db *sql.DB, m string) {
	_, _ = db.Exec(fmt.Sprintf("DROP STABLE IF EXISTS iot_e2e.%s", m))
	_ = db.Close()
}

// assertTDengineCount polls row count to expected value.
func assertTDengineCount(t *testing.T, db *sql.DB, m string, want int) {
	var count int64
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		count = 0
		if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM iot_e2e.%s", m)).Scan(&count); err == nil && count == int64(want) {
			return
		}
		time.Sleep(time.Second)
	}
	require.EqualValues(t, want, count, "row count after concurrent writes")
}

func setupTimescaleTable(t *testing.T, dsn string) (*sql.DB, string) {
	db, err := sql.Open("postgres", dsn)
	require.Nil(t, err)
	m := fmt.Sprintf("e2e_conc_%d", uniqueSuffix())
	_, err = db.Exec(fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, temp_c double precision, humi_pct double precision)`, m))
	require.Nil(t, err, "create table")
	return db, m
}
