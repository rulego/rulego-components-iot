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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/stretchr/testify/assert"
)

// TestNodeInitUnsupportedDriver verifies that unsupported drivers fail during initialization.
func TestNodeInitUnsupportedDriver(t *testing.T) {
	node := &Node{}
	err := node.Init(types.NewConfig(), types.Configuration{
		"driver": "unknown",
	})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsupported tsdb driver")
}

// TestNodeOnMsgPromRemote verifies that the generic write node can delegate to promremote.
func TestNodeOnMsgPromRemote(t *testing.T) {
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&Node{})
	node, err := test.CreateAndInitNode("x/tsdbWrite", types.Configuration{
		"driver": "promremote",
		"url":    server.URL,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `[{"measurement":"cpu","tags":{"host":"srv1"},"fields":{"value":1.5},"timestamp":100}]`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tsdbwrite callback")
	}

	select {
	case body := <-requests:
		assert.NotEmpty(t, body)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tsdbwrite delegated request")
	}
}

// TestNodeAcquisitionMapping 配置 measurement 后，采集点数组透视为 SeriesPoint 落盘。
func TestNodeAcquisitionMapping(t *testing.T) {
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&Node{})
	node, err := test.CreateAndInitNode("x/tsdbWrite", types.Configuration{
		"driver":      "promremote",
		"url":         server.URL,
		"measurement": "device_metrics",
		"tags":        []map[string]interface{}{{"key": "deviceId", "value": "dev-001"}},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	// 输入为采集点数组（含一个坏点 error，应被过滤）
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `[{"name":"temperature","value":25.3,"timestamp":1000},{"name":"humidity","value":60,"timestamp":2000},{"name":"bad","error":"read failed"}]`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for mapping callback")
	}

	select {
	case body := <-requests:
		assert.Contains(t, body, "device_metrics")
		assert.Contains(t, body, "temperature")
		assert.Contains(t, body, "humidity")
		assert.NotContains(t, body, "bad") // 坏点被过滤
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for mapped request")
	}
}
