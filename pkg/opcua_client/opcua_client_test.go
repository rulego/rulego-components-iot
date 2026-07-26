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

package opcuaClient

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
)

// ToPointsData：OK 点填 Value+Timestamp，坏点填 Error；Name 优先级 names → DisplayName → NodeID。
func TestToPointsData(t *testing.T) {
	nodeIds := []string{"ns=2;s=A", "ns=2;s=B", "ns=2;s=C"}
	names := []string{"温度", "", ""}
	data := []Data{
		{NodeId: "ns=2;s=A", DisplayName: "Temp"},
		{NodeId: "ns=2;s=B", DisplayName: "Pressure"},
		{NodeId: "ns=2;s=C"},
	}
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	v, _ := ua.NewVariant(23.5)
	resp := &ua.ReadResponse{
		Results: []*ua.DataValue{
			{Status: ua.StatusOK, Value: v, ServerTimestamp: ts},
			{Status: ua.StatusOK, Value: v, ServerTimestamp: ts},
			{Status: ua.StatusBad},
		},
	}

	out := ToPointsData(nodeIds, names, data, resp)
	assert.Equal(t, 3, len(out))

	// 配置点名最优先
	assert.Equal(t, "温度", out[0].Name)
	assert.Equal(t, 23.5, out[0].Value)
	assert.Equal(t, ts.UnixNano(), out[0].Timestamp)
	assert.Empty(t, out[0].Error)

	// 无配置名时 DisplayName 次优
	assert.Equal(t, "Pressure", out[1].Name)

	// 坏点：无 DisplayName 时用 NodeID，Error 填入，Value/Timestamp 为零值
	assert.Equal(t, "ns=2;s=C", out[2].Name)
	assert.NotEmpty(t, out[2].Error)
	assert.Nil(t, out[2].Value)
	assert.Equal(t, int64(0), out[2].Timestamp)

	// names 为 nil 时回退 DisplayName → NodeID（endpoint 调用场景）
	out2 := ToPointsData(nodeIds, nil, data, resp)
	assert.Equal(t, "Temp", out2[0].Name)
	assert.Equal(t, "ns=2;s=C", out2[2].Name)
}
