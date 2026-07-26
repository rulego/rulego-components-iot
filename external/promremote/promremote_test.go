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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/stretchr/testify/assert"
)

// TestParseMsgPointsLine verifies that line protocol input is parsed before write.
func TestParseMsgPointsLine(t *testing.T) {
	msg := types.NewMsg(0, "test", types.TEXT, types.NewMetadata(), "cpu,host=a v=1 100")
	pts, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pts))
	assert.Equal(t, "cpu", pts[0].Measurement)
}

// TestWriteNodeOnMsg verifies that the PromRemote write node routes a successful write to Success.
func TestWriteNodeOnMsg(t *testing.T) {
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/promremoteWrite", types.Configuration{
		"url": server.URL,
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
		t.Fatal("timeout waiting for promremote write callback")
	}

	select {
	case body := <-requests:
		assert.NotEmpty(t, body)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for promremote request")
	}
}
