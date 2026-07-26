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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/engine"
	"github.com/rulego/rulego/test/assert"
	"github.com/simonvetter/modbus"

	_ "github.com/rulego/rulego-components-iot/external/tsdbwrite"
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
