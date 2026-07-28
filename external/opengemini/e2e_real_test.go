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

package opengemini

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openGemini/opengemini-client-go/opengemini"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
)

// TestE2E_OpenGemini 真实端到端：写 SeriesPoint 到 OpenGemini，SQL 查询验证落盘。
// 需设 E2E_OPENGEMINI_ADDR（host:port，如 localhost:8087）启用；未设则 skip。
func TestE2E_OpenGemini(t *testing.T) {
	addr := os.Getenv("E2E_OPENGEMINI_ADDR")
	if addr == "" {
		t.Skip("set E2E_OPENGEMINI_ADDR (e.g. localhost:8087) to enable real e2e test")
	}
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		t.Fatalf("E2E_OPENGEMINI_ADDR must be host:port, got %q", addr)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("invalid port in %q: %v", addr, err)
	}
	client, err := opengemini.NewClient(&opengemini.Config{
		Addresses: []opengemini.Address{{Host: parts[0], Port: port}},
	})
	assert.Nil(t, err)
	defer client.Close()

	database := "e2e_iot"
	// 环境变量已设即期望可跑：等待服务就绪，持续不可达按失败处理（CreateDatabase 幂等）
	if err := waitReady(60*time.Second, func() error { return client.CreateDatabase(database) }); err != nil {
		t.Fatalf("opengemini not reachable within 60s: %v", err)
	}
	d := newDriver(client)

	measurement := fmt.Sprintf("e2e_iot_%d", time.Now().UnixNano())
	ctx := context.Background()
	err = d.WritePoints(ctx, database, []tsdb.SeriesPoint{{
		Measurement: measurement,
		Tags:        map[string]string{"host": "e2e"},
		Fields:      map[string]interface{}{"value": 42.5},
		Timestamp:   time.Now().UnixNano(),
	}})
	assert.Nil(t, err, "write to OpenGemini")

	// OpenGemini 写入后可查需短暂等待
	time.Sleep(2 * time.Second)
	res, err := d.Query(ctx, database, fmt.Sprintf("select * from %s", measurement))
	assert.Nil(t, err)
	assert.True(t, len(res.Rows) > 0, "query should return the written point")
}

// waitReady 在时限内每隔 2s 重试 ready，全部失败返回最后错误。
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
