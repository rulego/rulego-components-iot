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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/stretchr/testify/assert"
)

// fluxCSV 带注解的 Flux 查询响应样本，列序：result/table/_start/_stop/_time/_value/_field/_measurement/host/region。
const fluxCSV = `#datatype,string,long,dateTime:RFC3339,dateTime:RFC3339,dateTime:RFC3339,double,string,string,string,string
#group,false,false,true,true,false,false,false,false,true,true
#default,_result,,,,,,,,,
,result,table,_start,_stop,_time,_value,_field,_measurement,host,region
,,0,2020-02-17T22:19:49.747562847Z,2020-02-18T22:19:49.747562847Z,2020-02-18T10:34:08.135814545Z,1.4,f,test,srv1,us
,,0,2020-02-17T22:19:49.747562847Z,2020-02-18T22:19:49.747562847Z,2020-02-18T22:08:44.850214724Z,6.6,f,test,srv2,eu

`

// TestQueryNodeInitUnsupportedDriver verifies that unsupported drivers fail during initialization.
func TestQueryNodeInitUnsupportedDriver(t *testing.T) {
	node := &QueryNode{}
	err := node.Init(types.NewConfig(), types.Configuration{
		"driver": "unknown",
	})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsupported tsdb driver")
}

// TestQueryNodeOnMsgInfluxDB verifies delegation to x/influxdbQuery and deterministic column order.
func TestQueryNodeOnMsgInfluxDB(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fluxCSV))
	}))
	defer server.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&QueryNode{})
	node, err := test.CreateAndInitNode("x/tsdbQuery", types.Configuration{
		"driver": "influxdb",
		"url":    server.URL,
		"bucket": "bucket0",
		"org":    "org0",
		"token":  "token0",
		"query":  `from(bucket:"bucket0") |> range(start:-1h)`,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	var gotData string
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Nil(t, err)
		assert.Equal(t, types.Success, relationType)
		gotData = msg.GetData()
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tsdbQuery callback")
	}

	var res struct {
		Columns []string                 `json:"Columns"`
		Rows    []map[string]interface{} `json:"Rows"`
	}
	assert.Nil(t, json.Unmarshal([]byte(gotData), &res))
	// 列序与 CSV 注解序一致
	assert.Equal(t, []string{"result", "table", "_start", "_stop", "_time", "_value", "_field", "_measurement", "host", "region"}, res.Columns)
	assert.Equal(t, 2, len(res.Rows))
	assert.Equal(t, "srv1", res.Rows[0]["host"])
	assert.Equal(t, 1.4, res.Rows[0]["_value"])
}

// TestQueryNodeOnMsgFailure verifies that query errors route to Failure.
func TestQueryNodeOnMsgFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "query failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&QueryNode{})
	node, err := test.CreateAndInitNode("x/tsdbQuery", types.Configuration{
		"driver": "influxdb",
		"url":    server.URL,
		"bucket": "bucket0",
		"org":    "org0",
		"token":  "token0",
		"query":  `from(bucket:"bucket0") |> range(start:-1h)`,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tsdbQuery failure callback")
	}
}
