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

package tsdbwrite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	_ "github.com/lib/pq"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/stretchr/testify/assert"
	_ "github.com/taosdata/driver-go/v3/taosRestful"
)

// chainPoints 采集点数组：temperature/humidity 将被映射，pressure 未映射应被筛掉。
func chainPoints() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf(
		`[{"name":"temperature","value":25.3,"timestamp":%d},{"name":"humidity","value":60,"timestamp":%d},{"name":"pressure","value":101,"timestamp":%d}]`,
		now, now, now)
}

// mappingConfig 采集数据映射：measurement + host tag + fields 筛选/重命名。
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

// runWriteChain 构建单节点 x/tsdbWrite 规则链并发送采集点数组，同步等待完成。
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

// TestE2EChain_InfluxDB 规则链组合：采集点数组 -> x/tsdbWrite(influxdb) -> Flux 查询读回。
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

// TestE2EChain_TimescaleDB 规则链组合：采集点数组 -> x/tsdbWrite(timescaledb) -> SQL 查询读回。
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
	if _, err = db.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, temp_c double precision, humi_pct double precision)`, m)); err != nil {
		t.Skipf("create table failed (db not ready?): %v", err)
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

// TestE2EChain_TDengine 规则链组合：采集点数组 -> x/tsdbWrite(tdengine) -> SQL 查询读回。
func TestE2EChain_TDengine(t *testing.T) {
	dsn := os.Getenv("E2E_TDENGINE_DSN")
	if dsn == "" {
		t.Skip("set E2E_TDENGINE_DSN to enable real chain e2e")
	}
	db, err := sql.Open("taosRestful", dsn)
	assert.Nil(t, err)
	defer db.Close()
	ctx := context.Background()
	if _, err = db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS iot_e2e"); err != nil {
		t.Skipf("create database failed (tdengine not ready?): %v", err)
	}
	m := fmt.Sprintf("e2e_chain_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, fmt.Sprintf(
		"CREATE TABLE iot_e2e.%s (ts TIMESTAMP, host NCHAR(32), temp_c DOUBLE, humi_pct DOUBLE)", m)); err != nil {
		t.Skipf("create table failed: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf("DROP TABLE iot_e2e.%s", m)) }()

	config := mappingConfig(m)
	config["driver"] = "tdengine"
	config["dsn"] = dsn
	config["db"] = "iot_e2e"
	runWriteChain(t, "e2e_chain_tdengine", config)

	var host string
	var tempC, humiPct float64
	row := db.QueryRowContext(ctx, fmt.Sprintf("SELECT host, temp_c, humi_pct FROM iot_e2e.%s", m))
	assert.Nil(t, row.Scan(&host, &tempC, &humiPct))
	assert.Equal(t, "e2e", host)
	assert.Equal(t, 25.3, tempC)
	assert.Equal(t, float64(60), humiPct)
}

// TestE2EChain_PromRemote 规则链组合：采集点数组 -> x/tsdbWrite(promremote) -> VictoriaMetrics query 读回。
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

	time.Sleep(2 * time.Second)
	// 多 field 时 promremote 把 metric 名拼为 measurement_field
	assert.True(t, vmHasSeries(t, vm, m+"_temp_c"), "mapped metric %s_temp_c should exist", m)
	assert.True(t, vmHasSeries(t, vm, m+"_humi_pct"), "mapped metric %s_humi_pct should exist", m)
}

// vmHasSeries 查询 VictoriaMetrics 即时序列是否存在。
func vmHasSeries(t *testing.T, vm, metric string) bool {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/query?query=%s", vm, metric))
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
