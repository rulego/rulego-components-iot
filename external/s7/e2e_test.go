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

package s7

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_S7 真实端到端：对真实/模拟 S7 服务读 DB1 两个 FLOAT32 点。
// 需先起 S7 服务（如 python-snap7 server，DB1.DBD0=25.5、DB1.DBD4=80.25），
// 设 E2E_S7_ADDR（host:port，默认端口 102）启用；未设则 skip。
func TestE2E_S7(t *testing.T) {
	addr := os.Getenv("E2E_S7_ADDR")
	if addr == "" {
		t.Skip("set E2E_S7_ADDR (e.g. 192.168.60.19:102) to enable real e2e test")
	}
	node := &ReadNode{}
	err := node.Init(types.NewConfig(), types.Configuration{
		"server": addr,
		"rack":   0,
		"slot":   1,
		"points": []map[string]interface{}{
			{"name": "temp", "addr": "DB1.DBD0", "type": "FLOAT32"},
			{"name": "pressure", "addr": "DB1.DBD4", "type": "FLOAT32"},
		},
	})
	require.Nil(t, err, "init s7 read node")
	defer node.Destroy()

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: "{}"}},
		func(msg types.RuleMsg, relationType string, err error) {
			require.Equal(t, types.Success, relationType, "read should succeed: %v", err)
			var datas []iot_points.Data
			require.Nil(t, json.Unmarshal([]byte(msg.GetData()), &datas))
			got := map[string]float64{}
			for _, d := range datas {
				require.Empty(t, d.Error, "point %s error", d.Name)
				v, convErr := strconv.ParseFloat(fmt.Sprint(d.Value), 64)
				require.Nil(t, convErr, "point %s value %v to float", d.Name, d.Value)
				got[d.Name] = v
			}
			assert.Equal(t, 25.5, got["temp"], "DB1.DBD0")
			assert.Equal(t, 80.25, got["pressure"], "DB1.DBD4")
			done <- struct{}{}
		})

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for s7 read callback")
	}
}

// TestConcurrent_S7Read 8 并发 ×10 消息共享同一 x/s7Read 节点读取，验证值正确且无数据竞争。
func TestConcurrent_S7Read(t *testing.T) {
	addr := os.Getenv("E2E_S7_ADDR")
	if addr == "" {
		t.Skip("set E2E_S7_ADDR to enable concurrent test")
	}
	dsl := map[string]interface{}{
		"ruleChain": map[string]interface{}{"id": "e2e_conc_s7", "root": true},
		"metadata": map[string]interface{}{
			"firstNodeIndex": 0,
			"nodes": []map[string]interface{}{
				{"id": "r", "type": "x/s7Read", "configuration": map[string]interface{}{
					"server": addr,
					"rack":   0,
					"slot":   1,
					"points": []map[string]interface{}{
						{"name": "temp", "addr": "DB1.DBD0", "type": "FLOAT32"},
					},
				}},
			},
		},
	}
	b, err := json.Marshal(dsl)
	require.Nil(t, err)
	rg, err := rulego.New("e2e_conc_s7", b)
	require.Nil(t, err, "create rule engine")
	defer rulego.Del("e2e_conc_s7")

	var ok, bad int64
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				var done sync.WaitGroup
				done.Add(1)
				msg := types.NewMsg(0, "R", types.JSON, types.NewMetadata(), "{}")
				rg.OnMsg(msg, types.WithOnEnd(func(ctx types.RuleContext, m types.RuleMsg, e error, relationType string) {
					defer done.Done()
					if relationType != types.Success {
						atomic.AddInt64(&bad, 1)
						return
					}
					var datas []iot_points.Data
					if e := json.Unmarshal([]byte(m.GetData()), &datas); e != nil || len(datas) != 1 {
						atomic.AddInt64(&bad, 1)
						return
					}
					v, _ := strconv.ParseFloat(fmt.Sprint(datas[0].Value), 64)
					if v != 25.5 {
						atomic.AddInt64(&bad, 1)
					} else {
						atomic.AddInt64(&ok, 1)
					}
				}))
				done.Wait()
			}
		}()
	}
	wg.Wait()
	require.Zero(t, bad, "bad reads")
	require.EqualValues(t, 80, ok)
}
