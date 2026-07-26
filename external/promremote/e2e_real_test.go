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

package promremote

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/castai/promwrite"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
)

// TestE2E_VictoriaMetrics 真实端到端：写 SeriesPoint 到 VictoriaMetrics，查询验证值。
// 需先起 VictoriaMetrics（test/e2e/docker-compose.yml 或 docker run -p 8428:8428 victoriametrics/victoria-metrics），
// 设 E2E_VICTORIAMETRICS_URL=http://localhost:8428 启用；未设则 skip。
func TestE2E_VictoriaMetrics(t *testing.T) {
	base := os.Getenv("E2E_VICTORIAMETRICS_URL")
	if base == "" {
		t.Skip("set E2E_VICTORIAMETRICS_URL (e.g. http://localhost:8428) to enable real e2e test")
	}
	base = strings.TrimRight(base, "/")
	client := promwrite.NewClient(base + "/api/v1/write")
	d := newDriver(client, nil)

	metric := fmt.Sprintf("e2e_iot_%d", time.Now().UnixNano())
	now := time.Now().UnixNano()
	err := d.WritePoints(context.Background(), "", []tsdb.SeriesPoint{{
		Measurement: metric,
		Tags:        map[string]string{"host": "e2e"},
		Fields:      map[string]interface{}{"value": 42.5},
		Timestamp:   now,
	}})
	assert.Nil(t, err, "write to VictoriaMetrics")

	// 查询验证（VictoriaMetrics 索引需短暂等待）
	time.Sleep(time.Second)
	q := url.QueryEscape(fmt.Sprintf(`%s{host="e2e"}`, metric))
	resp, err := http.Get(base + "/api/v1/query?query=" + q)
	assert.Nil(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "42.5", "VictoriaMetrics should return the written value")
}
