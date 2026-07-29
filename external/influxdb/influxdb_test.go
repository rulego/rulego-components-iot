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

package influxdb

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/stretchr/testify/assert"
)

func TestParseLine(t *testing.T) {
	// With timestamp
	p, err := tsdb.ParseLine("cpu,host=srv1 value=72.5 1700000000000000000")
	assert.Nil(t, err)
	assert.Equal(t, "cpu", p.Measurement)
	assert.Equal(t, "srv1", p.Tags["host"])
	assert.Equal(t, 72.5, p.Fields["value"])
	assert.Equal(t, int64(1700000000000000000), p.Timestamp)

	// Without timestamp -> use current time
	p2, err := tsdb.ParseLine("temp,loc=a v=23")
	assert.Nil(t, err)
	assert.NotEqual(t, int64(0), p2.Timestamp)

	// 无 i 后缀的数值按 line protocol 标准解析为 float64
	p3, err := tsdb.ParseLine("m,k=v f=100")
	assert.Nil(t, err)
	assert.Equal(t, float64(100), p3.Fields["f"])
}

func TestParseLineProtocol(t *testing.T) {
	pts, err := tsdb.ParseLineProtocol("cpu,host=a v=1 100\ncpu,host=b v=2 200\n\n")
	assert.Nil(t, err)
	assert.Equal(t, 2, len(pts))
	assert.Equal(t, "a", pts[0].Tags["host"])
	assert.Equal(t, "b", pts[1].Tags["host"])
}

func TestParseMsgPointsJSON(t *testing.T) {
	msg := types.NewMsg(0, "test", types.JSON, types.NewMetadata(),
		`[{"measurement":"cpu","tags":{"h":"a"},"fields":{"v":1},"timestamp":100}]`)
	pts, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "cpu", pts[0].Measurement)
	assert.Equal(t, "a", pts[0].Tags["h"])
	assert.Equal(t, int64(100), pts[0].Timestamp)
}

func TestParseMsgPointsLine(t *testing.T) {
	msg := types.NewMsg(0, "test", types.TEXT, types.NewMetadata(), "cpu,host=a v=1 100")
	pts, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "cpu", pts[0].Measurement)
}

// TestWriteNodeOnMsg verifies that the write node routes a successful write to Success.
func TestWriteNodeOnMsg(t *testing.T) {
	type requestRecord struct {
		path string
		body string
	}
	requests := make(chan requestRecord, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- requestRecord{path: r.URL.Path, body: string(body)}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/influxdbWrite", types.Configuration{
		"url":    server.URL,
		"bucket": "bucket0",
		"org":    "org0",
		"token":  "token0",
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
		t.Fatal("timeout waiting for influxdb write callback")
	}

	select {
	case req := <-requests:
		assert.Equal(t, "/api/v2/write", req.path)
		assert.Contains(t, req.body, "cpu,host=srv1")
		assert.Contains(t, req.body, "value=1.5")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for influxdb write request")
	}
}

// TestToQueryResultColumnsOrder verifies Columns follow the Flux CSV annotation order.
func TestToQueryResultColumnsOrder(t *testing.T) {
	csv := `#datatype,string,long,dateTime:RFC3339,double,string,string
#group,false,false,true,false,false,true
#default,_result,,,,,
,result,table,_time,_value,_field,_measurement
,,0,2020-02-18T10:34:08.135814545Z,1.4,f,test
,,0,2020-02-18T22:08:44.850214724Z,6.6,f,test

`
	result := api.NewQueryTableResult(io.NopCloser(strings.NewReader(csv)))
	res, err := toQueryResult(result)
	assert.Nil(t, err)
	assert.Equal(t, []string{"result", "table", "_time", "_value", "_field", "_measurement"}, res.Columns)
	assert.Equal(t, 2, len(res.Rows))
	assert.Equal(t, 1.4, res.Rows[0]["_value"])
	assert.Equal(t, "test", res.Rows[0]["_measurement"])
}

// TestToQueryResultEmpty verifies empty results serialize as empty arrays instead of null.
func TestToQueryResultEmpty(t *testing.T) {
	csv := `#datatype,string,long,dateTime:RFC3339,double,string,string
#group,false,false,true,false,false,true
#default,_result,,,,,
,result,table,_time,_value,_field,_measurement

`
	result := api.NewQueryTableResult(io.NopCloser(strings.NewReader(csv)))
	res, err := toQueryResult(result)
	assert.Nil(t, err)
	assert.NotNil(t, res.Columns)
	assert.Equal(t, 0, len(res.Rows))
	data, merr := json.Marshal(res)
	assert.Nil(t, merr)
	assert.Contains(t, string(data), `"Rows":[]`)
}

// TestQueryNodeOnMsg verifies that the query node routes remote query errors to Failure.
func TestQueryNodeOnMsg(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "query failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&QueryNode{})
	node, err := test.CreateAndInitNode("x/influxdbQuery", types.Configuration{
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
		t.Fatal("timeout waiting for influxdb query callback")
	}
}
