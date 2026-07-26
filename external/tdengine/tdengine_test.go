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

package tdengine

import (
	"database/sql"
	"testing"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/utils/el"
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

func TestEscapeSingleQuotes(t *testing.T) {
	assert.Equal(t, "''", escapeSingleQuotes("'"))
	assert.Equal(t, "O''Neil", escapeSingleQuotes("O'Neil"))
}

func TestFormatValue(t *testing.T) {
	assert.Equal(t, "'test'", formatValue("test"))
	assert.Equal(t, "123", formatValue(123))
	assert.Equal(t, "123.45", formatValue(123.45))
	assert.Equal(t, "TRUE", formatValue(true))
	assert.Equal(t, "FALSE", formatValue(false))
}

// TestWriteNodeOnMsg verifies that invalid payloads are routed to Failure before database execution.
func TestWriteNodeOnMsg(t *testing.T) {
	node := &WriteNode{
		Config: WriteConfig{
			DB: "db0",
		},
	}
	node.dbTemplate, _ = el.NewTemplate(node.Config.DB)
	err := node.SharedNode.InitWithClose(types.NewConfig(), node.Type(), "mock://tdengine", false, func() (*sql.DB, error) {
		return &sql.DB{}, nil
	}, func(db *sql.DB) error {
		return nil
	})
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{"measurement":"cpu"`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tdengine write callback")
	}
}

// TestQueryNodeOnMsg verifies that missing clients are routed to Failure.
func TestQueryNodeOnMsg(t *testing.T) {
	node := &QueryNode{
		WriteNode: &WriteNode{
			Config: WriteConfig{
				DB: "db0",
			},
		},
		Config: QueryConfig{
			DB:    "db0",
			Query: "select * from cpu_load",
		},
	}
	node.dbTemplate, _ = el.NewTemplate(node.Config.DB)
	node.queryTemplate, _ = el.NewTemplate(node.Config.Query)
	node.queryHasVar = node.queryTemplate.HasVar()

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.ErrorIs(t, err, base.ErrClientNotInit)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tdengine query callback")
	}
}
