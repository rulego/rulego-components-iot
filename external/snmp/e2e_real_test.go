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

package snmp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

// TestE2E_SNMP 真实端到端：对真实 snmpd 执行 get + walk。
// 需先起 snmpd（v2c community=public），设 E2E_SNMP_ADDR（host 或 host:port）启用；未设则 skip。
func TestE2E_SNMP(t *testing.T) {
	addr := os.Getenv("E2E_SNMP_ADDR")
	if addr == "" {
		t.Skip("set E2E_SNMP_ADDR (e.g. 192.168.60.19) to enable real e2e test")
	}
	node := &ReadNode{}
	err := node.Init(types.NewConfig(), types.Configuration{
		"server":    addr,
		"community": "public",
		"version":   "v2c",
		"points": []map[string]interface{}{
			{"name": "sysDescr", "addr": "1.3.6.1.2.1.1.1.0"},
			{"name": "ifDescr", "addr": "walk:1.3.6.1.2.1.2.2.1.2"},
		},
	})
	require.Nil(t, err, "init snmp read node")
	defer node.Destroy()

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{DataType: types.JSON, MsgType: "TEST", Data: "{}"}},
		func(msg types.RuleMsg, relationType string, err error) {
			require.Equal(t, types.Success, relationType, "read should succeed: %v", err)
			var datas []iot_points.Data
			t.Logf("RAW DATA: %s", msg.GetData())
			require.Nil(t, json.Unmarshal([]byte(msg.GetData()), &datas))
			var gotDescr bool
			walkCount := 0
			for _, d := range datas {
				require.Empty(t, d.Error, "point %s error", d.Name)
				if d.Name == "sysDescr" {
					assert.Contains(t, octetString(d.Value), "Linux", "sysDescr from snmpd")
					gotDescr = true
				}
				if strings.HasPrefix(d.Name, "ifDescr") {
					walkCount++
				}
			}
			assert.True(t, gotDescr, "sysDescr point should be read")
			assert.Greater(t, walkCount, 0, "walk ifDescr should return at least one entry (lo)")
			done <- struct{}{}
		})

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for snmp read callback")
	}
}

// octetString 还原 OctetString 值：JSON 序列化后 []byte 表现为 base64 字符串。
func octetString(v interface{}) string {
	s := fmt.Sprint(v)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return s
}

// TestConcurrent_SNMPRead 8 并发 ×10 消息共享同一 x/snmpRead 节点读取，验证全部成功且值正确。
func TestConcurrent_SNMPRead(t *testing.T) {
	addr := os.Getenv("E2E_SNMP_ADDR")
	if addr == "" {
		t.Skip("set E2E_SNMP_ADDR to enable concurrent test")
	}
	dsl := map[string]interface{}{
		"ruleChain": map[string]interface{}{"id": "e2e_conc_snmp", "root": true},
		"metadata": map[string]interface{}{
			"firstNodeIndex": 0,
			"nodes": []map[string]interface{}{
				{"id": "r", "type": "x/snmpRead", "configuration": map[string]interface{}{
					"server":    addr,
					"community": "public",
					"version":   "v2c",
					"points": []map[string]interface{}{
						{"name": "sysDescr", "addr": "1.3.6.1.2.1.1.1.0"},
					},
				}},
			},
		},
	}
	b, err := json.Marshal(dsl)
	require.Nil(t, err)
	rg, err := rulego.New("e2e_conc_snmp", b)
	require.Nil(t, err, "create rule engine")
	defer rulego.Del("e2e_conc_snmp")

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
					if !strings.Contains(octetString(datas[0].Value), "Linux") {
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
