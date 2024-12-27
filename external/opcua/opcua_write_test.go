package opcua

import (
	"testing"

	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

func TestWriteNode(t *testing.T) {
	Registry := &types.SafeComponentSlice{}
	Registry.Add(&WriteNode{})
	var writeNodeType = "x/opcuaWrite"

	t.Run("NewNode", func(t *testing.T) {
		test.NodeNew(t, writeNodeType, &WriteNode{}, types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			"policy": "none",
			"mode":   "none",
			"auth":   "anonymous",
		}, Registry)
	})

	meta := types.BuildMetadata(make(map[string]string))
	data := `[{"timestamp":"2024-12-26T14:51:06.0038815+08:00","displayName":"Constant","nodeId":"ns=3;i=1001","recordTime":"2024-12-26T06:51:06Z","sourceTime":"2024-12-26T06:51:06Z","value":101,"quality":0},{"nodeId":"ns=3;i=1009","recordTime":"2024-12-26T06:51:06Z","sourceTime":"2024-12-26T06:51:06Z","value":3.5,"quality":0,"timestamp":"2024-12-26T14:51:06.0038815+08:00","displayName":"SWC_TP"}]`

	msgList := []test.Msg{
		{
			MetaData: meta,
			DataType: types.JSON,
			MsgType:  opcuaClient.OPC_UA_DATA_MSG_TYPE,
			Data:     data,
		},
	}

	t.Run("NodeOnMsg", func(t *testing.T) {
		node, _ := test.CreateAndInitNode(writeNodeType, types.Configuration{
			"server": "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			"policy": "none",
			"mode":   "none",
			"auth":   "anonymous",
		}, Registry)

		test.NodeOnMsg(t, node, msgList, func(msg types.RuleMsg, relationType string, err error) {
			assert.Equal(t, types.Success, relationType)
			assert.Equal(t, msg.Data, data)
		})
	})

}
