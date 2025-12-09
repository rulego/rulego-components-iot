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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/rulego/rulego"
	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// 注册节点
func init() {
	_ = rulego.Registry.Register(&WriteNode{})
}

// WriteNodeConfiguration  节点配置
type WriteNodeConfiguration struct {
	//OPC UA Server Endpoint, eg. opc.tcp://localhost:4840
	Server string `json:"server"`
	//Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256
	Policy string `json:"policy"`
	//Security Mode: one of None, Sign, SignAndEncrypt
	Mode string `json:"mode"`
	//Authentication Mode: one of Anonymous, UserName, Certificate
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
	//OPC UA Server CertFile Path
	CertFile string `json:"certFile"`
	//OPC UA Server CertKeyFile Path
	CertKeyFile string `json:"certKeyFile"`
}

func (c WriteNodeConfiguration) GetServer() string {
	return c.Server
}
func (c WriteNodeConfiguration) GetPolicy() string {
	return c.Policy
}
func (c WriteNodeConfiguration) GetMode() string {
	return c.Mode
}
func (c WriteNodeConfiguration) GetAuth() string {
	return c.Auth
}
func (c WriteNodeConfiguration) GetUsername() string {
	return c.Username
}
func (c WriteNodeConfiguration) GetPassword() string {
	return c.Password
}
func (c WriteNodeConfiguration) GetCertFile() string {
	return c.CertFile
}
func (c WriteNodeConfiguration) GetCertKeyFile() string {
	return c.CertKeyFile
}

// WriteNode opcua写入节点
// 把消息负荷 msg.Data 点位数据写入到opcua服务器，格式为：
//
//	[
//	  {
//	    "nodeId": "ns=3;i=1009",
//	    "value": 1
//	  },
//	  {
//	    "nodeId": "ns=3;i=1010",
//	    "value": 2
//	  }
//	]
//
// 写入成功，流转到`Success`链
// 否则流程转到`Failure`链
type WriteNode struct {
	base.SharedNode[*opcua.Client]
	//节点配置
	Config WriteNodeConfiguration
}

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: WriteNodeConfiguration{
			Server: "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy: "None",
			Mode:   "none",
			Auth:   "anonymous",
		},
	}
}

// Type 返回组件类型
func (x *WriteNode) Type() string {
	return "x/opcuaWrite"
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	_ = x.SharedNode.InitWithClose(x.RuleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*opcua.Client, error) {
		return x.initClient()
	}, func(client *opcua.Client) error {
		return client.Close(context.Background())
	})
	return err
}

// OnMsg 实现 Node 接口，处理消息
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	data := make([]opcuaClient.Data, 0)
	err = json.Unmarshal([]byte(msg.GetData()), &data)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	nodesToWrite := make([]*ua.WriteValue, 0)

	for _, d := range data {
		id, err := ua.ParseNodeID(d.NodeId)
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}

		v, err := ua.NewVariant(castValue(d.Value, d.DataType))
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
		nodesToWrite = append(nodesToWrite, &ua.WriteValue{
			NodeID:      id,
			AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        v,
			},
		})
	}

	req := &ua.WriteRequest{
		NodesToWrite: nodesToWrite,
	}

	resp, err := client.Write(context.Background(), req)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	succ := false
	var errs []string // 移除预分配的大小，避免空字符串
	if resp != nil {
		for _, result := range resp.Results {
			if result == ua.StatusOK {
				succ = true
			} else {
				errs = append(errs, result.Error())
			}
		}
	}
	if succ {
		ctx.TellSuccess(msg)
	} else {
		if len(errs) > 0 {
			ctx.TellFailure(msg, fmt.Errorf("write failed: %v", errs))
		} else {
			ctx.TellFailure(msg, fmt.Errorf("write failed with unknown error"))
		}
	}
}

// Destroy 清理资源
func (x *WriteNode) Destroy() {
	_ = x.SharedNode.Close()
}

func (x *WriteNode) initClient() (*opcua.Client, error) {
	client, err := opcuaClient.DefaultHolder(x.Config).NewOpcUaClient()
	return client, err
}

// castValue 尝试将 []interface{} 转换为特定类型的切片，以便 ua.NewVariant 可以正确处理
// castValue attempts to convert []interface{} to a slice of a specific type so that ua.NewVariant can handle it correctly
func castValue(val interface{}, dataType string) interface{} {
	if dataType != "" {
		return castValueByType(val, dataType)
	}
	switch v := val.(type) {
	case []interface{}:
		if len(v) == 0 {
			return v
		}
		// 根据第一个元素的类型进行转换
		// Convert based on the type of the first element
		switch v[0].(type) {
		case float64:
			arr := make([]float64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = f
				} else {
					return val // 如果类型不一致，返回原始值 | If types are inconsistent, return the original value
				}
			}
			return arr
		case string:
			arr := make([]string, len(v))
			for i, e := range v {
				if s, ok := e.(string); ok {
					arr[i] = s
				} else {
					return val
				}
			}
			return arr
		case bool:
			arr := make([]bool, len(v))
			for i, e := range v {
				if b, ok := e.(bool); ok {
					arr[i] = b
				} else {
					return val
				}
			}
			return arr
		}
	}
	return val
}

func castValueByType(val interface{}, dataType string) interface{} {
	dataType = strings.ToLower(dataType)
	// 检查是否为数组类型
	// Check if it is an array type
	if v, ok := val.([]interface{}); ok {
		switch dataType {
		case "boolean":
			arr := make([]bool, len(v))
			for i, e := range v {
				if b, ok := e.(bool); ok {
					arr[i] = b
				}
			}
			return arr
		case "sbyte":
			arr := make([]int8, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int8(f)
				}
			}
			return arr
		case "byte":
			arr := make([]byte, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = byte(f)
				}
			}
			return arr
		case "int16":
			arr := make([]int16, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int16(f)
				}
			}
			return arr
		case "uint16":
			arr := make([]uint16, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = uint16(f)
				}
			}
			return arr
		case "int32":
			arr := make([]int32, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int32(f)
				}
			}
			return arr
		case "uint32":
			arr := make([]uint32, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = uint32(f)
				}
			}
			return arr
		case "int64":
			arr := make([]int64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int64(f)
				}
			}
			return arr
		case "uint64":
			arr := make([]uint64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = uint64(f)
				}
			}
			return arr
		case "float":
			arr := make([]float32, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = float32(f)
				}
			}
			return arr
		case "double":
			arr := make([]float64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = f
				}
			}
			return arr
		case "string":
			arr := make([]string, len(v))
			for i, e := range v {
				if s, ok := e.(string); ok {
					arr[i] = s
				}
			}
			return arr
		case "datetime":
			arr := make([]time.Time, len(v))
			for i, e := range v {
				if s, ok := e.(string); ok {
					if t, err := time.Parse(time.RFC3339, s); err == nil {
						arr[i] = t
					}
				}
			}
			return arr
		}
	}

	// 标量类型处理
	// Scalar type handling
	switch dataType {
	case "boolean":
		if v, ok := val.(bool); ok {
			return v
		}
	case "sbyte":
		if v, ok := val.(float64); ok {
			return int8(v)
		}
	case "byte":
		if v, ok := val.(float64); ok {
			return byte(v)
		}
	case "int16":
		if v, ok := val.(float64); ok {
			return int16(v)
		}
	case "uint16":
		if v, ok := val.(float64); ok {
			return uint16(v)
		}
	case "int32":
		if v, ok := val.(float64); ok {
			return int32(v)
		}
	case "uint32":
		if v, ok := val.(float64); ok {
			return uint32(v)
		}
	case "int64":
		if v, ok := val.(float64); ok {
			return int64(v)
		}
	case "uint64":
		if v, ok := val.(float64); ok {
			return uint64(v)
		}
	case "float":
		if v, ok := val.(float64); ok {
			return float32(v)
		}
	case "double":
		if v, ok := val.(float64); ok {
			return v
		}
	case "string":
		if v, ok := val.(string); ok {
			return v
		}
	case "datetime":
		if v, ok := val.(string); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				return t
			}
		}
	case "guid":
		if v, ok := val.(string); ok {
			// 如果需要支持 GUID，需要实现 ParseGUID 或者使用第三方库
			// 暂时移除 ParseGUID 调用，避免编译错误
			// if id, err := ua.ParseGUID(v); err == nil {
			// 	return *id
			// }
			return v
		}
	}
	return val
}
