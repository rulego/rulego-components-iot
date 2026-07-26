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

// Package iec104 提供 IEC 60870-5-104 电力远动协议主站(控制站)的读取(ReadNode)节点,
// 用于电力调度/电网/变电站监控场景采集子站(被控站)的遥信/遥测/遥脉。
//
// 用法：
//   - 定时采集：前置 endpoint/schedule,点位在下方 points 配置(addr=信息体地址 IOA)。
//   - 按需读：msg.Data 带点位列表则优先使用(动态场景)。
//
// 采集模型：读时发起总召唤(GI),子站上送全数据后按 IOA 取值。
// 点位字段均支持 ${msg.xx} / ${metadata.xx} 模板变量。
package iec104

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rulego/rulego"
	iec104client "github.com/rulego/rulego-components-iot/pkg/iec104_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// 注册节点
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// Configuration 连接配置
type Configuration struct {
	// 子站地址,格式 host:port,IEC 104 默认端口 2404
	Server string `json:"server" label:"Server" desc:"host:port, default port 2404" required:"true" ref:"primary"`
	// 公共地址(CA/站址),默认 1
	CommonAddr int `json:"commonAddr" label:"CommonAddr" desc:"common address of ASDU, default 1"`
	// 总召唤等待超时(秒),默认 5
	Timeout int `json:"timeout" label:"Timeout" desc:"interrogation wait timeout in seconds, default 5"`
	// 默认点位表(addr=IOA)。定时采集(schedule 触发)时使用;msg.Data 带点位则优先
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table (addr=IOA); msg.Data points take precedence"`
}

// GetServer 实现 iec104client.ConfigProp
func (c Configuration) GetServer() string { return c.Server }

// GetCommonAddr 实现 iec104client.ConfigProp
func (c Configuration) GetCommonAddr() int { return c.CommonAddr }

// GetTimeout 实现 iec104client.ConfigProp
func (c Configuration) GetTimeout() int { return c.Timeout }

// iec104Reconnecter 连接重建能力接口。
type iec104Reconnecter interface {
	reconnect(old *iec104client.Client) (*iec104client.Client, error)
}

// ------------------------------------------------------------------------------------------------
// ReadNode IEC 104 读节点
// ------------------------------------------------------------------------------------------------

// ReadNode 发起总召唤批量采集子站点位,结果(统一契约 Data 列表)写回 msg.Data,经 Success 链转出。
//
// 输入(msg.Data 可选)：点位列表 JSON,格式同 points 配置。空则用配置的 points。
// 输出(msg.Data)：[{"name","value","timestamp","error"}]（timestamp 为 ns；error 仅单点失败时存在）
type ReadNode struct {
	base.SharedNode[*iec104client.Client]
	Config Configuration
	// reconnectLocker 保护重连
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *ReadNode) Type() string {
	return "x/iec104Read"
}

// New 默认配置
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:     "127.0.0.1:2404",
			CommonAddr: 1,
			Timeout:    5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "100", Type: "M_SP_NA_1"},
			},
		},
	}
}

// Init 初始化
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*iec104client.Client, error) {
		return iec104client.DefaultHolder(x.Config).NewClient()
	}, func(client *iec104client.Client) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	// 启用同链连接池：本地连接按节点ID注册到链目录,供链内 ref:// 借用复用
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg 处理消息。连接级失败自动重连重试 maxRetries 次。
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no iec104 points: configure points or pass [{...}] via msg.Data"))
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
		data, rerr := newDriver(client).ReadPoints(rendered)
		if rerr == nil {
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
		lastErr = rerr
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("read failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, rerr)
			oldClient := client
			newClient, cerr := x.reconnect(oldClient)
			if cerr != nil {
				ctx.TellFailure(msg, cerr)
				return
			}
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接。
func (x *ReadNode) reconnect(old *iec104client.Client) (*iec104client.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(iec104Reconnecter); ok {
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("iec104 ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		_ = old.Close()
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := iec104client.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[IEC104] "+format, v...)
	}
}

// Destroy 清理资源
func (x *ReadNode) Destroy() {
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *ReadNode) Desc() string {
	return "IEC 60870-5-104 master for reading substation points via interrogation. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode IEC 104 写节点（遥控/遥调）
// ------------------------------------------------------------------------------------------------

// WriteNode 向子站下发遥控(单命令/双命令)或遥调(设点)命令。
//
// 输入(msg.Data)：点位列表 JSON [{"name","addr","type","value"}]，
//   - addr=IOA（信息体地址）
//   - type=命令类型：C_SC_NA_1(单命令) / C_DC_NA_1(双命令) / C_SE_NB_1(标度化设点) / C_SE_NC_1(短浮点设点)
//   - value：单命令 true/false；双命令 1(合)/2(分)；设点为数值
type WriteNode struct {
	base.SharedNode[*iec104client.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *WriteNode) Type() string {
	return "x/iec104Write"
}

// New 默认配置
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:     "127.0.0.1:2404",
			CommonAddr: 1,
			Timeout:    5,
		},
	}
}

// Init 初始化
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*iec104client.Client, error) {
		return iec104client.DefaultHolder(x.Config).NewClient()
	}, func(client *iec104client.Client) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg 处理消息。从 msg.Data 解析点位列表,逐点下发控制命令。写入失败自动重连重试。
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no iec104 write points: pass [{\"addr\",\"type\",\"value\"}] via msg.Data"))
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
		werr := newDriver(client).WritePoints(rendered)
		if werr == nil {
			ctx.TellSuccess(msg)
			return
		}
		lastErr = werr
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, werr)
			oldClient := client
			newClient, cerr := x.reconnect(oldClient)
			if cerr != nil {
				ctx.TellFailure(msg, cerr)
				return
			}
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接（语义同 ReadNode.reconnect）
func (x *WriteNode) reconnect(old *iec104client.Client) (*iec104client.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(iec104Reconnecter); ok {
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("iec104 ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		_ = old.Close()
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := iec104client.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[IEC104] "+format, v...)
	}
}

// Destroy 清理资源
func (x *WriteNode) Destroy() {
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *WriteNode) Desc() string {
	return "IEC 60870-5-104 master for control commands (single/double/setpoint). Routes to Success/Failure"
}
