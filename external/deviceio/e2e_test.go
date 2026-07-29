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

package deviceio

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/golang/snappy"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	_ "github.com/lib/pq"
	opengeminiclient "github.com/openGemini/opengemini-client-go/opengemini"
	"github.com/prometheus/prometheus/prompb"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/engine"
	"github.com/rulego/rulego/test/assert"
	"github.com/simonvetter/modbus"
	"github.com/stretchr/testify/require"
	_ "github.com/taosdata/driver-go/v3/taosRestful"

	// endpoint 类型注册
	_ "github.com/rulego/rulego/endpoint/mqtt"
	_ "github.com/rulego/rulego/endpoint/rest"
	_ "github.com/rulego/rulego/endpoint/schedule"

	_ "github.com/rulego/rulego-components-iot/external/tsdb"
	_ "github.com/rulego/rulego-components-iot/transform/iot_to_series"
)

// e2eHandler 内存 modbus server，仅 holding register 读。
type e2eHandler struct {
	mu sync.Mutex
	hr map[uint16]uint16
}

func (h *e2eHandler) HandleCoils(*modbus.CoilsRequest) ([]bool, error) { return nil, nil }
func (h *e2eHandler) HandleDiscreteInputs(*modbus.DiscreteInputsRequest) ([]bool, error) {
	return nil, nil
}
func (h *e2eHandler) HandleInputRegisters(*modbus.InputRegistersRequest) ([]uint16, error) {
	return nil, nil
}
func (h *e2eHandler) HandleHoldingRegisters(req *modbus.HoldingRegistersRequest) ([]uint16, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.IsWrite {
		return nil, nil
	}
	res := make([]uint16, 0, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		res = append(res, h.hr[req.Addr+i])
	}
	return res, nil
}

// TestEndToEnd_ModbusToPromremote 端到端：modbus 采集 -> tsdbWrite(promremote，AcquisitionMapping 透视)。
// 全进程内 mock，不依赖硬件。解码 snappy+prompb 验证落盘语义：metric=device、值=23.5、无 timestamp 假序列。
func TestEndToEnd_ModbusToPromremote(t *testing.T) {
	// 1. modbus server 预填 40001 = FLOAT32 23.5 (0x41bc0000, ABCD: regs [0x41bc, 0x0000])
	h := &e2eHandler{hr: map[uint16]uint16{0: 0x41bc, 1: 0x0000}}
	server, err := modbus.NewServer(&modbus.ServerConfiguration{URL: "tcp://127.0.0.1:5510"}, h)
	assert.Nil(t, err)
	assert.Nil(t, server.Start())
	defer server.Stop()
	time.Sleep(100 * time.Millisecond) // 等 server listen

	// 2. promremote HTTP mock（存原始 snappy body）
	var gotBody []byte
	var bodyMu sync.Mutex
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyMu.Lock()
		gotBody = b
		bodyMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer prom.Close()

	// 3. DSL 链：iotRead(modbus) -> tsdbWrite(promremote，AcquisitionMapping 透视 temp_c<-temp)
	dsl := fmt.Sprintf(`{
		"ruleChain":{"id":"e2e","name":"e2e","root":true,"debugMode":false},
		"metadata":{"nodes":[
			{"id":"read","type":"x/iotRead","name":"read","configuration":{"driver":"modbus","server":"tcp://127.0.0.1:5510","unitId":1,"points":[{"name":"temp","addr":"40001","type":"FLOAT32"}],"encodingConfig":{"endianness":1,"wordOrder":1},"tcpConfig":{"timeout":5}}},
			{"id":"w","type":"x/tsdbWrite","name":"w","configuration":{"driver":"promremote","url":"%s","measurement":"device","fields":[{"key":"temp_c","source":"temp"}]}}
		],"connections":[
			{"fromId":"read","toId":"w","type":"Success"}
		]}
	}`, prom.URL)

	config := rulego.NewConfig(
		types.WithDefaultPool(),
		types.WithOnDebug(func(chainId, flowType, nodeId string, msg types.RuleMsg, relation string, err error) {
			if err != nil {
				t.Logf("[debug] %s/%s %s: %v", chainId, nodeId, relation, err)
			}
		}),
	)
	rg, err := rulego.New("e2e", []byte(dsl), engine.WithConfig(config))
	assert.Nil(t, err, "create rule engine")
	defer rg.Stop(context.Background())

	// 4. 触发链（msg 触发 iotRead 读配置的 points，经 AcquisitionMapping 透视后落盘）
	rg.OnMsg(types.NewMsg(0, "TRIGGER", types.JSON, types.NewMetadata(), ""))

	// 5. 等 promremote 收到写入请求
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		bodyMu.Lock()
		received := len(gotBody) > 0
		bodyMu.Unlock()
		if received {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	bodyMu.Lock()
	defer bodyMu.Unlock()

	// 6. 解码 snappy + prompb，验证落盘语义
	decoded, err := snappy.Decode(nil, gotBody)
	assert.Nil(t, err, "snappy decode")
	var req prompb.WriteRequest
	assert.Nil(t, req.Unmarshal(decoded), "prompb unmarshal")
	// AcquisitionMapping 只透视 value 为字段：仅 1 条序列（无 name/timestamp 假序列）
	assert.Equal(t, 1, len(req.Timeseries), "should write exactly 1 series")
	labels := map[string]string{}
	for _, l := range req.Timeseries[0].Labels {
		labels[l.Name] = l.Value
	}
	assert.Equal(t, "device", labels["__name__"])
	assert.Equal(t, 1, len(req.Timeseries[0].Samples))
	assert.Equal(t, 23.5, req.Timeseries[0].Samples[0].Value)
}

// TestEndToEnd_ModbusToInfluxDB 端到端标杆：
// modbus 进程内 server 采集 -> x/iotRead -> x/tsdbWrite(influxdb，配 measurement/fields 映射) -> Flux 查询读回。
// 验证「采集点数组 → SeriesPoint 可选映射」在规则链与真实 TSDB 下的完整链路。
// 需设 E2E_INFLUXDB_URL/E2E_INFLUXDB_TOKEN 启用；未设则 skip。
func TestEndToEnd_ModbusToInfluxDB(t *testing.T) {
	url := os.Getenv("E2E_INFLUXDB_URL")
	token := os.Getenv("E2E_INFLUXDB_TOKEN")
	if url == "" || token == "" {
		t.Skip("set E2E_INFLUXDB_URL and E2E_INFLUXDB_TOKEN to enable modbus->influxdb e2e")
	}
	org := os.Getenv("E2E_INFLUXDB_ORG")
	if org == "" {
		org = "rulego"
	}
	bucket := os.Getenv("E2E_INFLUXDB_BUCKET")
	if bucket == "" {
		bucket = "iot"
	}

	// 1. modbus server 预填 40001 = FLOAT32 23.5 (ABCD: regs [0x41bc, 0x0000])
	h := &e2eHandler{hr: map[uint16]uint16{0: 0x41bc, 1: 0x0000}}
	server, err := modbus.NewServer(&modbus.ServerConfiguration{URL: "tcp://127.0.0.1:5511"}, h)
	assert.Nil(t, err)
	assert.Nil(t, server.Start())
	defer server.Stop()
	time.Sleep(100 * time.Millisecond)

	// 2. 规则链：iotRead(modbus) -> tsdbWrite(influxdb，配 fields 映射 temp_c<-temp)
	m := fmt.Sprintf("e2e_modbus_%d", time.Now().UnixNano())
	dsl := fmt.Sprintf(`{
		"ruleChain":{"id":"e2e_modbus_influx","root":true},
		"metadata":{"nodes":[
			{"id":"read","type":"x/iotRead","configuration":{"driver":"modbus","server":"tcp://127.0.0.1:5511","unitId":1,"points":[{"name":"temp","addr":"40001","type":"FLOAT32"}],"encodingConfig":{"endianness":1,"wordOrder":1},"tcpConfig":{"timeout":5}}},
			{"id":"w","type":"x/tsdbWrite","configuration":{"driver":"influxdb","url":"%s","token":"%s","org":"%s","bucket":"%s","measurement":"%s","tags":[{"key":"host","value":"e2e"}],"fields":[{"key":"temp_c","source":"temp"}]}}
		],"connections":[
			{"fromId":"read","toId":"w","type":"Success"}
		]}
	}`, url, token, org, bucket, m)

	rg, err := rulego.New("e2e_modbus_influx", []byte(dsl))
	assert.Nil(t, err, "create rule engine")
	defer rg.Stop(context.Background())

	rg.OnMsg(types.NewMsg(0, "TRIGGER", types.JSON, types.NewMetadata(), ""))

	// 3. 轮询查询 influxdb 直到 temp_c 可查（采集+落盘+索引需时间）
	client := influxdb2.NewClient(url, token)
	defer client.Close()
	flux := fmt.Sprintf(
		`from(bucket:"%s") |> range(start:-5m) |> filter(fn:(r)=>r._measurement=="%s") |> filter(fn:(r)=>r._field=="temp_c")`,
		bucket, m)
	deadline := time.Now().Add(15 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		res, qerr := client.QueryAPI(org).Query(context.Background(), flux)
		if qerr == nil && res.Next() {
			if v, ok := res.Record().Value().(float64); ok && v > 23.0 && v < 24.0 {
				found = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	assert.True(t, found, "modbus -> tsdbWrite(influxdb) should persist mapped field temp_c=23.5")
}

// parseOGAddr 解析 host:port 为 OpenGemini 客户端地址列表。
func parseOGAddr(t *testing.T, addr string) []opengeminiclient.Address {
	t.Helper()
	parts := strings.Split(addr, ":")
	require.Equal(t, 2, len(parts), "addr must be host:port")
	port, err := strconv.Atoi(parts[1])
	require.Nil(t, err)
	return []opengeminiclient.Address{{Host: parts[0], Port: port}}
}

// s7ChainDSL 组装「S7 采集 -> tsdbWrite」两节点链 DSL。
func s7ChainDSL(chainID, s7Addr, writeCfg string) string {
	return fmt.Sprintf(`{
		"ruleChain":{"id":"%s","root":true},
		"metadata":{"nodes":[
			{"id":"read","type":"x/iotRead","configuration":{"driver":"s7","server":"%s","rack":0,"slot":1,"points":[
				{"name":"temp","addr":"DB1.DBD0","type":"FLOAT32"},
				{"name":"pressure","addr":"DB1.DBD4","type":"FLOAT32"}
			]}},
			{"id":"w","type":"x/tsdbWrite","configuration":%s}
		],"connections":[
			{"fromId":"read","toId":"w","type":"Success"}
		]}
	}`, chainID, s7Addr, writeCfg)
}

// triggerAndWait 触发链一次并轮询 cond 至真（上限 wait）。
func triggerAndWait(t *testing.T, chainID, dsl string, wait time.Duration, cond func() bool) {
	t.Helper()
	rg, err := rulego.New(chainID, []byte(dsl))
	require.Nil(t, err, "create rule engine")
	defer rulego.Del(chainID)
	rg.OnMsg(types.NewMsg(0, "TRIGGER", types.JSON, types.NewMetadata(), ""))
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.True(t, cond(), "condition not met within %s", wait)
}

// TestEndToEnd_S7ToTDengine S7 采集 -> x/tsdbWrite(tdengine) -> 读回核对。
func TestEndToEnd_S7ToTDengine(t *testing.T) {
	s7Addr := os.Getenv("E2E_S7_ADDR")
	dsn := os.Getenv("E2E_TDENGINE_DSN")
	if s7Addr == "" || dsn == "" {
		t.Skip("set E2E_S7_ADDR and E2E_TDENGINE_DSN to enable s7->tdengine e2e")
	}
	db, err := sql.Open("taosRestful", dsn)
	require.Nil(t, err)
	defer db.Close()
	m := fmt.Sprintf("e2e_s7chain_%d", time.Now().UnixNano())
	_, err = db.Exec(fmt.Sprintf(
		"CREATE STABLE iot_e2e.%s (ts TIMESTAMP, temp_c DOUBLE, press DOUBLE) TAGS (`host` NCHAR(32))", m))
	require.Nil(t, err, "create stable")
	defer func() { _, _ = db.Exec(fmt.Sprintf("DROP STABLE IF EXISTS iot_e2e.%s", m)) }()

	writeCfg := fmt.Sprintf(`{"driver":"tdengine","dsn":"%s","db":"iot_e2e","measurement":"%s",
		"tags":[{"key":"host","value":"e2e"}],
		"fields":[{"key":"temp_c","source":"temp"},{"key":"press","source":"pressure"}]}`, dsn, m)
	found := func() bool {
		var tempC, press float64
		if e := db.QueryRow(fmt.Sprintf("SELECT temp_c, press FROM iot_e2e.%s", m)).Scan(&tempC, &press); e != nil {
			return false
		}
		return tempC == 25.5 && press == 80.25
	}
	triggerAndWait(t, "e2e_s7_tdengine", s7ChainDSL("e2e_s7_tdengine", s7Addr, writeCfg), 15*time.Second, found)
}

// TestEndToEnd_S7ToTimescaleDB S7 采集 -> x/tsdbWrite(timescaledb) -> 读回核对。
func TestEndToEnd_S7ToTimescaleDB(t *testing.T) {
	s7Addr := os.Getenv("E2E_S7_ADDR")
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if s7Addr == "" || dsn == "" {
		t.Skip("set E2E_S7_ADDR and E2E_TIMESCALEDB_DSN to enable s7->timescaledb e2e")
	}
	db, err := sql.Open("postgres", dsn)
	require.Nil(t, err)
	defer db.Close()
	m := fmt.Sprintf("e2e_s7chain_%d", time.Now().UnixNano())
	_, err = db.Exec(fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, temp_c double precision, press double precision)`, m))
	require.Nil(t, err, "create table")
	defer func() { _, _ = db.Exec(fmt.Sprintf(`DROP TABLE public.%s`, m)) }()

	writeCfg := fmt.Sprintf(`{"driver":"timescaledb","dsn":"%s","db":"public","measurement":"%s",
		"tags":[{"key":"host","value":"e2e"}],
		"fields":[{"key":"temp_c","source":"temp"},{"key":"press","source":"pressure"}]}`, dsn, m)
	found := func() bool {
		var host string
		var tempC, press float64
		if e := db.QueryRow(fmt.Sprintf(`SELECT host, temp_c, press FROM public.%s`, m)).Scan(&host, &tempC, &press); e != nil {
			return false
		}
		return host == "e2e" && tempC == 25.5 && press == 80.25
	}
	triggerAndWait(t, "e2e_s7_timescale", s7ChainDSL("e2e_s7_timescale", s7Addr, writeCfg), 15*time.Second, found)
}

// TestEndToEnd_S7ToOpenGemini S7 采集 -> x/tsdbWrite(opengemini) -> 读回核对。
func TestEndToEnd_S7ToOpenGemini(t *testing.T) {
	s7Addr := os.Getenv("E2E_S7_ADDR")
	addr := os.Getenv("E2E_OPENGEMINI_ADDR")
	if s7Addr == "" || addr == "" {
		t.Skip("set E2E_S7_ADDR and E2E_OPENGEMINI_ADDR to enable s7->opengemini e2e")
	}
	client, err := opengeminiclient.NewClient(&opengeminiclient.Config{Addresses: parseOGAddr(t, addr)})
	require.Nil(t, err)
	defer client.Close()
	_ = client.CreateDatabase("e2e_iot")
	m := fmt.Sprintf("e2e_s7chain_%d", time.Now().UnixNano())

	writeCfg := fmt.Sprintf(`{"driver":"opengemini","server":"%s","database":"e2e_iot","measurement":"%s",
		"tags":[{"key":"host","value":"e2e"}],
		"fields":[{"key":"temp_c","source":"temp"},{"key":"press","source":"pressure"}]}`, addr, m)
	found := func() bool {
		res, e := client.Query(opengeminiclient.Query{Database: "e2e_iot", Command: fmt.Sprintf("select * from %s", m)})
		if e != nil || len(res.Results) == 0 || res.Results[0] == nil {
			return false
		}
		for _, s := range res.Results[0].Series {
			for _, row := range s.Values {
				var hit bool
				for _, v := range row {
					if f, ok := v.(float64); ok && f == 25.5 {
						hit = true
					}
				}
				if hit {
					return true
				}
			}
		}
		return false
	}
	triggerAndWait(t, "e2e_s7_opengemini", s7ChainDSL("e2e_s7_opengemini", s7Addr, writeCfg), 15*time.Second, found)
}

// TestEndToEnd_S7ToSeriesToTimescaleDB 三节点链：S7 采集 -> x/iotToSeries 转换 -> x/tsdbWrite -> 读回核对。
func TestEndToEnd_S7ToSeriesToTimescaleDB(t *testing.T) {
	s7Addr := os.Getenv("E2E_S7_ADDR")
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if s7Addr == "" || dsn == "" {
		t.Skip("set E2E_S7_ADDR and E2E_TIMESCALEDB_DSN to enable s7->iotToSeries->timescaledb e2e")
	}
	db, err := sql.Open("postgres", dsn)
	require.Nil(t, err)
	defer db.Close()
	m := fmt.Sprintf("e2e_s7series_%d", time.Now().UnixNano())
	_, err = db.Exec(fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, temp_c double precision)`, m))
	require.Nil(t, err, "create table")
	defer func() { _, _ = db.Exec(fmt.Sprintf(`DROP TABLE public.%s`, m)) }()

	dsl := fmt.Sprintf(`{
		"ruleChain":{"id":"e2e_s7_series","root":true},
		"metadata":{"nodes":[
			{"id":"read","type":"x/iotRead","configuration":{"driver":"s7","server":"%s","rack":0,"slot":1,"points":[
				{"name":"temp","addr":"DB1.DBD0","type":"FLOAT32"}
			]}},
			{"id":"conv","type":"x/iotToSeries","configuration":{"measurement":"%s","tags":{"host":"e2e"},"fields":{"temp_c":"value"},"timestampField":"timestamp"}},
			{"id":"w","type":"x/tsdbWrite","configuration":{"driver":"timescaledb","dsn":"%s","db":"public"}}
		],"connections":[
			{"fromId":"read","toId":"conv","type":"Success"},
			{"fromId":"conv","toId":"w","type":"Success"}
		]}
	}`, s7Addr, m, dsn)
	found := func() bool {
		var host string
		var tempC float64
		if e := db.QueryRow(fmt.Sprintf(`SELECT host, temp_c FROM public.%s`, m)).Scan(&host, &tempC); e != nil {
			return false
		}
		return host == "e2e" && tempC == 25.5
	}
	triggerAndWait(t, "e2e_s7_series", dsl, 15*time.Second, found)
}

// startEndpointEngine 创建启用 endpoint 模块的规则引擎。
func startEndpointEngine(t *testing.T, chainID, dsl string) {
	t.Helper()
	config := rulego.NewConfig(types.WithDefaultPool())
	config.EndpointEnabled = true
	rg, err := rulego.New(chainID, []byte(dsl), engine.WithConfig(config))
	require.Nil(t, err, "create rule engine with endpoints")
	_ = rg // 引擎按 chainID 全局注册，t.Cleanup 统一注销
	t.Cleanup(func() { rulego.Del(chainID) })
}

// pollPG 轮询 PostgreSQL 查询直到 cond 满足或超时。
func pollPG(t *testing.T, dsn string, wait time.Duration, cond func(db *sql.DB) bool) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	require.Nil(t, err)
	defer db.Close()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if cond(db) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.True(t, cond(db), "condition not met within %s", wait)
}

// TestEndToEnd_ScheduleS7Collect 定时采集：endpoint/schedule 每秒触发 -> x/iotRead(s7) -> x/tsdbWrite(timescaledb)，
// 不手动发消息，等行数累积 >=3 验证持续落盘。
func TestEndToEnd_ScheduleS7Collect(t *testing.T) {
	s7Addr := os.Getenv("E2E_S7_ADDR")
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if s7Addr == "" || dsn == "" {
		t.Skip("set E2E_S7_ADDR and E2E_TIMESCALEDB_DSN to enable schedule e2e")
	}
	db, err := sql.Open("postgres", dsn)
	require.Nil(t, err)
	m := fmt.Sprintf("e2e_sched_%d", time.Now().UnixNano())
	_, err = db.Exec(fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, temp_c double precision)`, m))
	require.Nil(t, err, "create table")
	defer func() { _, _ = db.Exec(fmt.Sprintf(`DROP TABLE public.%s`, m)) }()
	db.Close()

	dsl := fmt.Sprintf(`{
		"ruleChain":{"id":"e2e_sched","root":true},
		"metadata":{
			"endpoints":[{
				"id":"sch","type":"endpoint/schedule",
				"routers":[{"from":{"path":"*/1 * * * * *"},"to":{"path":"e2e_sched:read"}}]
			}],
			"nodes":[
				{"id":"read","type":"x/iotRead","configuration":{"driver":"s7","server":"%s","rack":0,"slot":1,"points":[
					{"name":"temp","addr":"DB1.DBD0","type":"FLOAT32"}
				]}},
				{"id":"w","type":"x/tsdbWrite","configuration":{"driver":"timescaledb","dsn":"%s","db":"public","measurement":"%s",
					"tags":[{"key":"host","value":"e2e"}],
					"fields":[{"key":"temp_c","source":"temp"}]}}
			],
			"connections":[{"fromId":"read","toId":"w","type":"Success"}]
		}
	}`, s7Addr, dsn, m)
	startEndpointEngine(t, "e2e_sched", dsl)

	pollPG(t, dsn, 20*time.Second, func(q *sql.DB) bool {
		var count int
		if e := q.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM public.%s`, m)).Scan(&count); e != nil {
			return false
		}
		return count >= 3
	})
}

// TestEndToEnd_MqttToTimescaleDB MQTT 订阅：endpoint/mqtt 订阅 topic -> x/tsdbWrite(timescaledb)，
// 测试用 paho 客户端发布 SeriesPoint JSON 后读回核对。
func TestEndToEnd_MqttToTimescaleDB(t *testing.T) {
	broker := os.Getenv("E2E_MQTT_ADDR")
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if broker == "" || dsn == "" {
		t.Skip("set E2E_MQTT_ADDR (e.g. tcp://localhost:1883) and E2E_TIMESCALEDB_DSN to enable mqtt e2e")
	}
	db, err := sql.Open("postgres", dsn)
	require.Nil(t, err)
	m := fmt.Sprintf("e2e_mqtt_%d", time.Now().UnixNano())
	_, err = db.Exec(fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, value double precision)`, m))
	require.Nil(t, err, "create table")
	defer func() { _, _ = db.Exec(fmt.Sprintf(`DROP TABLE public.%s`, m)) }()
	db.Close()

	const topic = "rulego/e2e/telemetry"
	dsl := fmt.Sprintf(`{
		"ruleChain":{"id":"e2e_mqtt","root":true},
		"metadata":{
			"endpoints":[{
				"id":"ep","type":"endpoint/mqtt",
				"configuration":{"server":"%s"},
				"routers":[{"from":{"path":"%s"},"to":{"path":"e2e_mqtt:w"}}]
			}],
			"nodes":[
				{"id":"w","type":"x/tsdbWrite","configuration":{"driver":"timescaledb","dsn":"%s","db":"public"}}
			]
		}
	}`, broker, topic, dsn)
	startEndpointEngine(t, "e2e_mqtt", dsl)
	time.Sleep(2 * time.Second) // 等订阅建立

	opts := mqtt.NewClientOptions().AddBroker(broker).SetClientID(fmt.Sprintf("e2e_pub_%d", time.Now().UnixNano()))
	client := mqtt.NewClient(opts)
	require.True(t, client.Connect().WaitTimeout(10*time.Second), "mqtt connect timeout")
	defer client.Disconnect(100)

	payload := fmt.Sprintf(
		`[{"measurement":"%s","tags":{"host":"e2e"},"fields":{"value":42.5},"timestamp":%d}]`,
		m, time.Now().UnixNano())
	token := client.Publish(topic, 0, false, payload)
	require.True(t, token.WaitTimeout(10*time.Second), "mqtt publish timeout")

	pollPG(t, dsn, 15*time.Second, func(q *sql.DB) bool {
		var host string
		var v float64
		if e := q.QueryRow(fmt.Sprintf(`SELECT host, value FROM public.%s`, m)).Scan(&host, &v); e != nil {
			return false
		}
		return host == "e2e" && v == 42.5
	})
}

// TestEndToEnd_HttpToTimescaleDB HTTP 推送：endpoint/http 接收 POST 遥测 -> x/tsdbWrite(timescaledb)。
func TestEndToEnd_HttpToTimescaleDB(t *testing.T) {
	dsn := os.Getenv("E2E_TIMESCALEDB_DSN")
	if dsn == "" {
		t.Skip("set E2E_TIMESCALEDB_DSN to enable http endpoint e2e")
	}
	db, err := sql.Open("postgres", dsn)
	require.Nil(t, err)
	m := fmt.Sprintf("e2e_http_%d", time.Now().UnixNano())
	_, err = db.Exec(fmt.Sprintf(
		`CREATE TABLE public.%s (time timestamptz, host text, value double precision)`, m))
	require.Nil(t, err, "create table")
	defer func() { _, _ = db.Exec(fmt.Sprintf(`DROP TABLE public.%s`, m)) }()
	db.Close()

	const addr = ":19095"
	dsl := fmt.Sprintf(`{
		"ruleChain":{"id":"e2e_http","root":true},
		"metadata":{
			"endpoints":[{
				"id":"ep","type":"endpoint/http",
				"configuration":{"server":"%s"},
				"routers":[{"from":{"path":"/api/telemetry"},"params":["POST"],"to":{"path":"e2e_http:w"}}]
			}],
			"nodes":[
				{"id":"w","type":"x/tsdbWrite","configuration":{"driver":"timescaledb","dsn":"%s","db":"public"}}
			]
		}
	}`, addr, dsn)
	startEndpointEngine(t, "e2e_http", dsl)
	time.Sleep(500 * time.Millisecond) // 等 HTTP 监听就绪

	payload := fmt.Sprintf(
		`[{"measurement":"%s","tags":{"host":"e2e"},"fields":{"value":42.5},"timestamp":%d}]`,
		m, time.Now().UnixNano())
	resp, err := http.Post("http://localhost"+addr+"/api/telemetry", "application/json", strings.NewReader(payload))
	require.Nil(t, err, "http post")
	resp.Body.Close()

	pollPG(t, dsn, 15*time.Second, func(q *sql.DB) bool {
		var host string
		var v float64
		if e := q.QueryRow(fmt.Sprintf(`SELECT host, value FROM public.%s`, m)).Scan(&host, &v); e != nil {
			return false
		}
		return host == "e2e" && v == 42.5
	})
}
