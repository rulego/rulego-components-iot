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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gopcua/opcua"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
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
	Server string `json:"server" label:"Server" desc:"OPC UA server endpoint, format: opc.tcp://host:port" required:"true" ref:"primary"`
	//Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256
	Policy string `json:"policy" label:"Security Policy" desc:"Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256" ref:"shared" group:"advanced"`
	//Security Mode: one of None, Sign, SignAndEncrypt
	Mode string `json:"mode" label:"Security Mode" desc:"Security mode: None, Sign, SignAndEncrypt" ref:"shared" group:"advanced"`
	//Authentication Mode: one of Anonymous, UserName, Certificate
	Auth     string `json:"auth" label:"Auth Mode" desc:"Authentication mode: Anonymous, UserName, Certificate" ref:"shared" group:"advanced"`
	Username string `json:"username" label:"Username" desc:"Authentication username" ref:"shared" group:"advanced"`
	Password string `json:"password" label:"Password" desc:"Authentication password" ref:"shared" group:"advanced"`
	//OPC UA 客户端证书文件
	CertFile string `json:"certFile" label:"Cert File" desc:"Client certificate file path" ref:"shared" group:"advanced"`
	//OPC UA 客户端证书私钥文件
	CertKeyFile string `json:"certKeyFile" label:"Cert Key File" desc:"Client private key file path" ref:"shared" group:"advanced"`
	// 请求超时（秒）
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5" ref:"shared"`
	// 默认点位表（addr=NodeID，如 ns=2;s=Temperature）；为空则从 msg.Data 解析 nodeIds（旧兼容）
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points; addr=NodeID; empty=parse nodeIds from msg.Data"`
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
func (c Configuration) GetTimeout() int {
	return c.Timeout
}

// ReadNode 批量读取 OPC UA 节点，结果(统一契约 Data 列表)写回 msg.Data，经 Success 链转出。
// gopcua SecureChannel 按 RequestID 匹配响应，天然并发安全，无需 opLock。
//
// 点位来源（双入口，msg.Data 优先）：配置 points(addr=NodeID)；或 msg.Data 带 nodeIds/points。
// 输出(msg.Data)：[{"name","value","timestamp","error"}]
//
// opcuaReconnecter 连接重建能力接口。
type opcuaReconnecter interface {
	reconnect(old *opcua.Client) (*opcua.Client, error)
}

type ReadNode struct {
	base.SharedNode[*opcua.Client]
	//节点配置
	Config Configuration
	// reconnectLocker 保护重连
	reconnectLocker sync.Mutex
}

func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy:  "None",
			Mode:    "none",
			Auth:    "anonymous",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "temperature", Addr: "ns=2;s=Temperature"},
			},
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
	_ = x.SharedNode.InitWithClose(x.RuleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*opcua.Client, error) {
		return x.initClient()
	}, func(client *opcua.Client) error {
		return client.Close(context.Background())
	})
	// 启用同链连接池
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg 处理消息。点位双入口（msg.Data 优先，兼容旧 nodeIds/旧 write Data/新 points）；连接级失败自动重连重试。
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := resolvePoints(x.Config.Points, msg, errors.New("no opcua points: configure points or pass nodeIds/points via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rendered := make([]iot_points.Point, len(pts))
	for i := range pts {
		rendered[i] = iot_points.RenderPoint(pts[i], env)
	}
	var lastErr error
	for retry := 0; retry <= iot_points.DefaultMaxRetries; retry++ {
		data, err := newDriver(client, x.RuleConfig.Logger).ReadPoints(rendered)
		if err == nil {
			b, mErr := json.Marshal(data)
			if mErr != nil {
				ctx.TellFailure(msg, mErr)
				return
			}
			msg.SetDataType(types.JSON)
			msg.SetData(string(b))
			ctx.TellSuccess(msg)
			return
		}
		lastErr = err
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("read failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, err)
			newClient, rerr := x.reconnect(client)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// Destroy 清理资源
func (x *ReadNode) Destroy() {
	_ = x.SharedNode.Close()
}

// Desc returns the component description
func (x *ReadNode) Desc() string {
	return "OPC-UA client for reading node values. Routes to Success/Failure"
}

// Def returns the component form definition
func (x *ReadNode) Def() types.ComponentForm {
	return types.ComponentForm{}
}

func (x *ReadNode) initClient() (*opcua.Client, error) {
	client, err := opcuaClient.DefaultHolder(x.Config, x.RuleConfig.Logger).NewOpcUaClient()
	return client, err
}

// reconnect 安全重建连接。
func (x *ReadNode) reconnect(old *opcua.Client) (*opcua.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(opcuaReconnecter); ok { // 跨类型：Read↔Write 均可委派
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("opcua ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
	}
	x.reconnectLocker.Lock()
	defer x.reconnectLocker.Unlock()
	current, err := x.SharedNode.GetSafely()
	if err != nil {
		return nil, err
	}
	if current != old {
		return current, nil
	}
	if old != nil {
		_ = old.Close(context.Background())
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := x.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[OPCUA] "+format, v...)
	}
}
