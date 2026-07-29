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

// Package eip 提供罗克韦尔 ControlLogix/CompactLogix 通过 EtherNet/IP(CIP) 的
// 读取(ReadNode)与写入(WriteNode)节点。
//
// 用法：
//   - 定时采集：前置 endpoint/schedule，标签在下方 points 配置。
//   - 按需读/写：msg.Data 带点位列表则优先使用（动态场景）。
//
// 点位字段均支持 ${msg.xx} / ${metadata.xx} 模板变量。
// 因 gologix 的 Read 需要具体类型指针，点位需指定 type（BOOL/INT/DINT/REAL/STRING/...）。
package eip

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/danomagnum/gologix"
	"github.com/rulego/rulego"
	eipclient "github.com/rulego/rulego-components-iot/pkg/eip_client"
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

// Configuration 连接配置（读/写节点共用）
type Configuration struct {
	// PLC 地址，格式 host 或 host:port，默认端口 44818
	Server string `json:"server" label:"Server" desc:"host or host:port, default port 44818" required:"true" ref:"primary"`
	// CPU 在背板上的槽位号，默认 0，自动生成 CIP 路径
	Slot int `json:"slot" label:"Slot" desc:"CPU slot on backplane, default 0"`
	// 可选：手动覆盖 CIP 路径，如 1,0；留空则按 slot 自动生成
	Path string `json:"path" label:"Path" desc:"CIP path override, e.g. 1,0; empty=auto from slot"`
	// 请求超时(秒)，默认 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// 默认点位表。定时采集(schedule 触发)时使用；msg.Data 带点位则优先
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// GetServer 实现 eipclient.ConfigProp
func (c Configuration) GetServer() string { return c.Server }

// GetSlot 实现 eipclient.ConfigProp
func (c Configuration) GetSlot() int { return c.Slot }

// GetPath 实现 eipclient.ConfigProp
func (c Configuration) GetPath() string { return c.Path }

// GetTimeout 实现 eipclient.ConfigProp
func (c Configuration) GetTimeout() int { return c.Timeout }

// eipOpLocks 按底层 client 关联操作锁，串行化共享 client 的并发读写。
var eipOpLocks iot_points.OpLocks

// eipReconnecter 连接重建能力接口。
type eipReconnecter interface {
	reconnect(old *gologix.Client) (*gologix.Client, error)
}

// ------------------------------------------------------------------------------------------------
// ReadNode EtherNet/IP 读节点
// ------------------------------------------------------------------------------------------------

// ReadNode 批量读取 ControlLogix 标签，结果(统一契约 Data 列表)写回 msg.Data，经 Success 链转出。
//
// 输入(msg.Data 可选)：点位列表 JSON，格式同 points 配置。空则用配置的 points。
// 输出(msg.Data)：[{"name","value","timestamp","error"}]（timestamp 为 ns；error 仅单点失败时存在）
type ReadNode struct {
	base.SharedNode[*gologix.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *ReadNode) Type() string {
	return "x/eipRead"
}

// New 默认配置
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:44818",
			Slot:    0,
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "tag1", Addr: "MyTag", Type: "INT32"},
			},
		},
	}
}

// Init 初始化
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gologix.Client, error) {
		return eipclient.DefaultHolder(x.Config).NewClient()
	}, func(client *gologix.Client) error {
		if client != nil {
			return client.Disconnect()
		}
		return nil
	})
	// 启用同链连接池
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg 处理消息。连接级失败（全部标签失败）自动重连重试 maxRetries 次。
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no eip points: configure points or pass [{...}] via msg.Data"))
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
		data, err := func() ([]iot_points.Data, error) {
			opLock := eipOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client, x.RuleConfig.Logger).ReadPoints(rendered)
		}()
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
			oldClient := client
			newClient, rerr := x.reconnect(oldClient)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			eipOpLocks.Delete(oldClient) // 清理旧连接操作锁
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接。
func (x *ReadNode) reconnect(old *gologix.Client) (*gologix.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(eipReconnecter); ok { // 跨类型：Read↔Write 均可委派
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("eip ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		_ = old.Disconnect()
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := eipclient.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[EIP] "+format, v...)
	}
}

// Destroy 清理资源
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // 仅 owner 清理操作锁
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			eipOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *ReadNode) Desc() string {
	return "EtherNet/IP client for batch reading ControlLogix tags. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode EtherNet/IP 写节点
// ------------------------------------------------------------------------------------------------

// WriteNode 把 msg.Data 的标签值列表写入 ControlLogix，成功走 Success 链。
//
// 输入(msg.Data)：[{"name","addr","type","value"}]（addr 为 CIP tag 名），value 支持 ${msg.xx}
type WriteNode struct {
	base.SharedNode[*gologix.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *WriteNode) Type() string {
	return "x/eipWrite"
}

// New 默认配置
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:44818",
			Slot:    0,
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "tag1", Addr: "MyTag", Type: "INT32", Value: "${msg.value}"},
			},
		},
	}
}

// Init 初始化
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gologix.Client, error) {
		return eipclient.DefaultHolder(x.Config).NewClient()
	}, func(client *gologix.Client) error {
		if client != nil {
			return client.Disconnect()
		}
		return nil
	})
	// 启用同链连接池
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg 处理消息。写入失败自动重连重试 maxRetries 次。
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no eip points: configure points or pass [{...}] via msg.Data"))
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
		werr := func() error {
			opLock := eipOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client, x.RuleConfig.Logger).WritePoints(rendered)
		}()
		if werr == nil {
			ctx.TellSuccess(msg)
			return
		} else {
			lastErr = werr
		}
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, lastErr)
			oldClient := client
			newClient, rerr := x.reconnect(oldClient)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			eipOpLocks.Delete(oldClient) // 清理旧连接操作锁
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接（语义同 ReadNode.reconnect）
func (x *WriteNode) reconnect(old *gologix.Client) (*gologix.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(eipReconnecter); ok { // 跨类型：Read↔Write 均可委派
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("eip ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		_ = old.Disconnect()
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := eipclient.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[EIP] "+format, v...)
	}
}

// Destroy 清理资源
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			eipOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *WriteNode) Desc() string {
	return "EtherNet/IP client for writing ControlLogix tags. Routes to Success/Failure"
}
