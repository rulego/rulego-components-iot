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

// Package e2e 存放跨组件链路级端到端测试（真实环境，环境变量门控）。
// 组件自身的驱动级 e2e 测试仍放在各组件包下（如 external/opengemini/e2e_real_test.go）。
package e2e

// 链路：TCP 二进制帧接入(endpoint/net) -> JS 脚本解协议(jsTransform) -> 扁平 JSON
//       -> x/tsdbWrite(tdengine driver，配置 measurement 直接消费扁平 map) -> TDengine 查询读回。
// 引擎配置对齐 rulego server（独立用户池 + 自定义组件注册表 + 节点池）。
// 需要真实 TDengine：E2E_TDENGINE_DSN（如 root:taosdata@http(127.0.0.1:6041)/），未设置则跳过。
// 可选：E2E_TDENGINE_DB（默认 iot_e2e）、E2E_BIN_TCP_ADDR（默认 :19703）。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	_ "github.com/rulego/rulego-components-iot/external/tsdb"
	"github.com/rulego/rulego/engine"
	"github.com/rulego/rulego/node_pool"
	_ "github.com/taosdata/driver-go/v3/taosRestful"
)

// sensorFrame 温度湿度传感器上行帧：AA 55 | devID | cmd | len | payload(temp INT16 BE ×0.1, humi INT16 BE ×0.1) | xor | 0x0A 结尾
// dev=0x07 temp=25.6(0x0100) humi=60.5(0x025D) xor(07^01^04^01^00^02^5D)=5C（异或范围不含帧头）
func sensorFrame() []byte {
	return []byte{0xAA, 0x55, 0x07, 0x01, 0x04, 0x01, 0x00, 0x02, 0x5D, 0x5C, 0x0A}
}

// jsParseScript 解协议脚本：校验帧头/XOR，按大端取温湿度（×0.1 工程量），输出扁平 JSON。
const jsParseScript = `
function byteAt(b, i) { return b[i] & 0xff; }
function xorCheck(b, from, to) { var c = 0; for (var i = from; i < to; i++) { c ^= byteAt(b, i); } return c & 0xff; }
function int16BE(b, i) { var v = (byteAt(b, i) << 8) | byteAt(b, i + 1); return v > 32767 ? v - 65536 : v; }
var b = msg;
if (b.length < 10 || byteAt(b, 0) !== 0xAA || byteAt(b, 1) !== 0x55) { throw 'bad header: len=' + b.length; }
var devId = byteAt(b, 2);
var len = byteAt(b, 4);
if (b.length < 5 + len + 1) { throw 'short frame'; }
var crcIdx = 5 + len;
if (xorCheck(b, 2, crcIdx) !== byteAt(b, crcIdx)) { throw 'crc mismatch'; }
var hex = devId.toString(16);
var out = { deviceId: 'dev-' + (devId < 16 ? '0' : '') + hex, temperature: int16BE(b, 5) / 10, humidity: int16BE(b, 7) / 10 };
metadata['deviceId'] = out.deviceId;
return {'msg': out, 'metadata': metadata, 'msgType': 'SENSOR_DATA', 'dataType': 'JSON'};
`

func TestE2EChain_BinaryTCP_JS_TDengine(t *testing.T) {
	dsn := os.Getenv("E2E_TDENGINE_DSN")
	if dsn == "" {
		t.Skip("set E2E_TDENGINE_DSN (e.g. root:taosdata@http(127.0.0.1:6041)/) to enable real binary->JS->TDengine e2e")
	}
	db := os.Getenv("E2E_TDENGINE_DB")
	if db == "" {
		db = "iot_e2e"
	}
	tcpAddr := os.Getenv("E2E_BIN_TCP_ADDR")
	if tcpAddr == "" {
		tcpAddr = ":19703"
	}
	measurement := "e2e_bin_js"
	chainID := "e2e_chain_bin_js_tdengine"

	tds, err := sql.Open("taosRestful", dsn+db)
	if err != nil {
		t.Fatalf("open tdengine: %v", err)
	}
	defer tds.Close()
	// 建超级表（driver 写入时按 tags 自动建子表）
	if _, err := tds.Exec(fmt.Sprintf(
		"CREATE STABLE IF NOT EXISTS %s.%s (ts TIMESTAMP, temperature FLOAT, humidity FLOAT) TAGS (device_id NCHAR(64))",
		db, measurement)); err != nil {
		t.Fatalf("create stable: %v", err)
	}
	defer func() { _, _ = tds.Exec(fmt.Sprintf("DROP STABLE IF EXISTS %s.%s", db, measurement)) }()

	dsl := map[string]interface{}{
		"ruleChain": map[string]interface{}{"id": chainID, "root": true, "debugMode": true},
		"metadata": map[string]interface{}{
			"endpoints": []map[string]interface{}{{
				"id":   "ep_tcp",
				"type": "endpoint/net",
				"configuration": map[string]interface{}{
					"protocol":      "tcp",
					"server":        tcpAddr,
					"readTimeout":   300,
					"encode":        "",
					"packetMode":    "delimiter",
					"delimiter":     "0x0A",
					"maxPacketSize": 1024,
				},
				"routers": []map[string]interface{}{{
					"id":   "r1",
					"from": map[string]interface{}{"path": ".*", "processors": []string{"setBinaryDataType"}},
					"to":   map[string]interface{}{"path": chainID + ":js_parse", "processors": []string{"responseToBody"}},
				}},
			}},
			"nodes": []map[string]interface{}{
				{"id": "js_parse", "type": "jsTransform", "configuration": map[string]interface{}{"jsScript": jsParseScript}},
				{"id": "tsdb_write", "type": "x/tsdbWrite", "configuration": map[string]interface{}{
					"driver":      "tdengine",
					"dsn":         dsn,
					"db":          db,
					"measurement": measurement,
					"tags":        []map[string]interface{}{{"key": "device_id", "value": "${msg.deviceId}"}},
					"fields":      []map[string]interface{}{{"key": "temperature", "source": "temperature"}, {"key": "humidity", "source": "humidity"}},
				}},
			},
			"connections": []map[string]interface{}{
				{"fromId": "js_parse", "toId": "tsdb_write", "type": "Success"},
			},
		},
	}
	b, err := json.Marshal(dsl)
	if err != nil {
		t.Fatalf("marshal dsl: %v", err)
	}
	// 引擎配置对齐 rulego server：独立用户池 + 自定义组件注册表 + 节点池
	componentRegistry := engine.NewCustomComponentRegistry(engine.Registry, new(engine.RuleComponentRegistry))
	nodePool := node_pool.NewNodePool(rulego.NewConfig(types.WithComponentsRegistry(componentRegistry)))
	cfg := rulego.NewConfig(types.WithDefaultPool(),
		types.WithComponentsRegistry(componentRegistry),
		types.WithNodePool(nodePool),
		types.WithOnDebug(func(chainId, flowType string, nodeId string, msg types.RuleMsg, relationType string, err error) {
			if err != nil {
				t.Logf("[DEBUG] %s %s node=%s rel=%s err=%v", chainId, flowType, nodeId, relationType, err)
			}
		}))
	userPool := rulego.NewRuleGo()
	if _, err := userPool.New(chainID, b, engine.WithConfig(cfg)); err != nil {
		t.Fatalf("create rule engine: %v", err)
	}
	defer userPool.Del(chainID)
	time.Sleep(500 * time.Millisecond) // 等 TCP endpoint 起监听

	// 发送真实二进制帧
	conn, err := net.Dial("tcp", "127.0.0.1"+tcpAddr)
	if err != nil {
		t.Fatalf("dial tcp endpoint: %v", err)
	}
	if _, err := conn.Write(sensorFrame()); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	_ = conn.Close()

	// 轮询查询落盘结果（写入→读回有延迟）
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var temp, humi float64
		var dev string
		row := tds.QueryRow(fmt.Sprintf(
			"SELECT temperature, humidity, device_id FROM %s.%s ORDER BY ts DESC LIMIT 1", db, measurement))
		if err := row.Scan(&temp, &humi, &dev); err == nil {
			if temp == 25.6 && humi == 60.5 && dev == "dev-07" {
				return // 全链路通过
			}
			t.Fatalf("unexpected row: temp=%v humi=%v dev=%v, want 25.6/60.5/dev-07", temp, humi, dev)
		}
		time.Sleep(time.Second)
	}
	t.Fatal("no row landed in TDengine within 15s")
}
