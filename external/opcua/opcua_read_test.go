/*
 * Copyright 2024 The RuleGo Authors.
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

package opcua

import (
	"encoding/json"
	"testing"

	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

func TestReadNode(t *testing.T) {
	Registry := &types.SafeComponentSlice{}
	Registry.Add(&ReadNode{})
	var nodeType = "x/opcuaRead"

	// t.Run("NewNode", func(t *testing.T) {
	// 	test.NodeNew(t, nodeType, &ReadNode{}, types.Configuration{
	// 		"server": "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
	// 		"policy": "none",
	// 		"mode":   "none",
	// 		"auth":   "anonymous",
	// 	}, Registry)
	// })
	nodeIds := make([]string, 0)
	nodeIds = append(nodeIds, "ns=3;i=1101")
	nodeIds = append(nodeIds, "ns=3;i=1109")
	d, _ := json.Marshal(nodeIds)

	// meta := types.BuildMetadata(make(map[string]string))
	// meta.PutValue("nodeIds", string(d))

	msgList := []test.Msg{
		{
			MetaData: nil,
			DataType: types.JSON,
			MsgType:  opcuaClient.OPC_UA_DATA_MSG_TYPE,
			Data:     string(d),
		},
	}

	t.Run("NodeOnMsg", func(t *testing.T) {
		node, _ := test.CreateAndInitNode(nodeType, types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			"policy": "none",
			"mode":   "none",
			"auth":   "anonymous",
		}, Registry)

		test.NodeOnMsg(t, node, msgList, func(msg types.RuleMsg, relationType string, err error) {
			assert.Equal(t, types.Success, relationType)
			assert.Nil(t, err)
			assert.NotNil(t, msg.Data)
			t.Logf("data : %s ", msg.Data)
		})
	})

}
