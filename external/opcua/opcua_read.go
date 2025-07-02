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
	_ = rulego.Registry.Register(&ReadNode{})
}

// Configuration 节点配置
type Configuration struct {
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

func (c Configuration) GetServer() string {
	return c.Server
}
func (c Configuration) GetPolicy() string {
	return c.Policy
}
func (c Configuration) GetMode() string {
	return c.Mode
}
func (c Configuration) GetAuth() string {
	return c.Auth
}
func (c Configuration) GetUsername() string {
	return c.Username
}
func (c Configuration) GetPassword() string {
	return c.Password
}
func (c Configuration) GetCertFile() string {
	return c.CertFile
}
func (c Configuration) GetCertKeyFile() string {
	return c.CertKeyFile
}

// ReadNode opcua读取节点
// 查询消息负荷 msg.Data 中节点列表点位数据
// 节点列表格式：["ns=3;i=1003","ns=3;i=1005"]
// 查询结果会重新赋值到msg.Data，通过`Success`链传给下一个节点
// 结果格式：
// [
//
//	 {
//	   "displayName": "ns=3;i=1003",
//	   "floatValue": 0,
//	   "nodeId": "ns=3;i=1003",
//	   "quality": 0,
//	   "recordTime": "0001-01-01T00:00:00Z",
//	   "sourceTime": "0001-01-01T00:00:00Z",
//	   "timestamp": "0001-01-01T00:00:00Z",
//	}
//
// ]
type ReadNode struct {
	base.SharedNode[*opcua.Client]
	//节点配置
	Config Configuration
	client *opcua.Client
}

func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server: "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy: "None",
			Mode:   "none",
			Auth:   "anonymous",
		},
	}
}

// Type 返回组件类型
func (x *ReadNode) Type() string {
	return "x/opcuaRead"
}

func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	_ = x.SharedNode.Init(x.RuleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*opcua.Client, error) {
		return x.initClient()
	})
	return err
}

// OnMsg 实现 Node 接口，处理消息
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	// 开始操作，增加活跃操作计数
	x.SharedNode.BeginOp()
	defer x.SharedNode.EndOp()

	// 检查是否正在关闭
	if x.SharedNode.IsShuttingDown() {
		ctx.TellFailure(msg, fmt.Errorf("opcua read client is shutting down"))
		return
	}

	client, err := x.SharedNode.Get()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	// 再次检查是否正在关闭，防止在Get()之后被关闭
	if x.SharedNode.IsShuttingDown() {
		ctx.TellFailure(msg, fmt.Errorf("opcua read client is shutting down"))
		return
	}

	nodeIds := make([]string, 0)
	err = json.Unmarshal([]byte(msg.GetData()), &nodeIds)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	data, resp, err := opcuaClient.Read(client, nodeIds)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	succ := false
	errs := make([]string, 10)
	for i, result := range resp.Results {
		if result != nil && result.Status != ua.StatusOK {
			if len(errs) < 10 {
				//防止查询结果过多
				errs = append(errs, result.Status.Error())
			}
		} else {
			d := opcuaClient.Data{
				DisplayName: data[i].DisplayName,
				NodeId:      data[i].NodeId,
				RecordTime:  result.ServerTimestamp,
				SourceTime:  result.SourceTimestamp,
				Value:       result.Value.Value(),
				Quality:     uint32(result.Status),
				Timestamp:   time.Now(),
			}
			_, _ = d.ParseValue()
			data[i] = d
			succ = true
		}
	}
	if succ {
		if dbyte, err := json.Marshal(data); err != nil {
			ctx.TellFailure(msg, err)
		} else {
			msg.SetData(string(dbyte))
			ctx.TellSuccess(msg)
		}
	} else {
		ctx.TellFailure(msg, fmt.Errorf("read failed: %q ", errs))
	}
}

// Destroy 清理资源
func (x *ReadNode) Destroy() {
	// 使用优雅关闭机制，等待活跃操作完成后再关闭资源
	x.SharedNode.GracefulShutdown(0, func() {
		// 只在非资源池模式下关闭本地资源
		if x.client != nil {
			_ = x.client.Close(context.Background())
			x.client = nil
		}
	})
}

func (x *ReadNode) initClient() (*opcua.Client, error) {
	if x.client != nil {
		return x.client, nil
	} else {
		_, cancel := context.WithTimeout(context.TODO(), 4*time.Second)
		x.Locker.Lock()
		defer func() {
			cancel()
			x.Locker.Unlock()
		}()
		if x.client != nil {
			return x.client, nil
		}

		client, err := opcuaClient.DefaultHolder(x.Config).NewOpcUaClient()
		if err != nil {
			return nil, err
		}
		x.client = client
		return x.client, err
	}
}
