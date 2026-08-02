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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/castai/promwrite"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_VictoriaMetrics real end-to-end: write SeriesPoint to VictoriaMetrics, query and verify value.
// Requires VictoriaMetrics running first (test/e2e/docker-compose.yml or docker run -p 8428:8428 victoriametrics/victoria-metrics),
// set E2E_VICTORIAMETRICS_URL=http://localhost:8428 to enable; skip if not set.
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

	// Query verification: VM new series index creation has ~1 minute delay, poll query_range until queryable
	q := url.QueryEscape(fmt.Sprintf(`%s{host="e2e"}`, metric))
	ts := now / 1e9
	queryURL := base + "/api/v1/query_range?query=" + q +
		"&start=" + strconv.FormatInt(ts-60, 10) + "&end=" + strconv.FormatInt(ts+60, 10) + "&step=15"
	require.Eventually(t, func() bool {
		resp, err := http.Get(queryURL)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return strings.Contains(string(body), "42.5")
	}, 120*time.Second, 5*time.Second, "VictoriaMetrics should return the written value")
}
