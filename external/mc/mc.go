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

// Package mc 提供三菱 MC Protocol(3E 帧, 二进制)PLC 的读取(ReadNode)与写入(WriteNode)节点，
// 适用 Q/L/R/iQ-R/iQ-F 系列。
//
// 用法：
//   - 定时采集：前置 endpoint/schedule，点位在下方 points 配置。
//   - 按需读/写：msg.Data 带点位列表则优先使用（动态场景）。
//
// 点位 Addr 为三菱软元件地址：字软元件 D100/W10/R200/ZR10/TN5，位软元件 M0/X1F/Y0/B4。
// 点位字段均支持 ${msg.xx} / ${metadata.xx} 模板变量。
package mc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moge800/gomcprotocol"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// defaultPort MC 协议默认端口
const defaultPort = 6000

// 注册节点
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// Configuration 连接配置（读/写节点共用）。
// 注：网络号/PC号等站号参数由底层库固定为自局(00/FF/FF03/00)，覆盖以太网直连场景。
type Configuration struct {
	// PLC 地址，格式 host:port，默认端口 6000
	Server string `json:"server" label:"Server" desc:"Mitsubishi PLC host:port, MC default port 6000" required:"true" ref:"primary"`
	// 请求超时(秒)，默认 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// 默认点位表。定时采集(schedule 触发)时使用；msg.Data 带点位则优先
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// parseServer 解析 host:port；仅 host 时补默认端口 6000。
func parseServer(server string) (string, int, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", 0, errors.New("empty mc server")
	}
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return server, defaultPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid mc server %q", server)
	}
	return host, port, nil
}

// mcOpLocks 按底层 client 关联操作锁，串行化共享 client 的并发读写。
var mcOpLocks iot_points.OpLocks

// newClient 创建并连接 3E 帧二进制客户端。
func newClient(config Configuration) (*gomcprotocol.Client3E, error) {
	host, port, err := parseServer(config.Server)
	if err != nil {
		return nil, err
	}
	client, err := gomcprotocol.New3EClient(host, port, gomcprotocol.ModeBinary)
	if err != nil {
		return nil, err
	}
	if config.Timeout > 0 {
		client.SetTimeout(time.Duration(config.Timeout) * time.Second)
	}
	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

// mcReconnecter 连接重建能力接口。
type mcReconnecter interface {
	reconnect(old *gomcprotocol.Client3E) (*gomcprotocol.Client3E, error)
}

// ------------------------------------------------------------------------------------------------
// ReadNode MC 读节点
// ------------------------------------------------------------------------------------------------

// ReadNode 批量读取三菱 PLC 点位，结果(统一契约 Data 列表)写回 msg.Data，经 Success 链转出。
//
// 输入(msg.Data 可选)：点位列表 JSON，格式同 points 配置。空则用配置的 points。
// 输出(msg.Data)：[{"name","value","timestamp","error"}]
type ReadNode struct {
	base.SharedNode[*gomcprotocol.Client3E]
	Config Configuration
	// reconnectLocker 保护重连
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *ReadNode) Type() string {
	return "x/mcRead"
}

// New 默认配置
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:6000",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "D100", Type: "UINT16"},
			},
		},
	}
}

// Init 初始化
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gomcprotocol.Client3E, error) {
		return newClient(x.Config)
	}, func(client *gomcprotocol.Client3E) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	// 启用同链连接池
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg 处理消息。连接级失败（全部点位失败）自动重连重试 maxRetries 次。
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no mc points: configure points or pass [{...}] via msg.Data"))
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
		data, rerr := func() ([]iot_points.Data, error) {
			opLock := mcOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client).ReadPoints(rendered)
		}()
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
			mcOpLocks.Delete(oldClient)
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接。
func (x *ReadNode) reconnect(old *gomcprotocol.Client3E) (*gomcprotocol.Client3E, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(mcReconnecter); ok {
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("mc ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	client, err := newClient(x.Config)
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(client)
	return client, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[MC] "+format, v...)
	}
}

// Destroy 清理资源
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			mcOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *ReadNode) Desc() string {
	return "Mitsubishi MC protocol client for batch reading PLC points. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode MC 写节点
// ------------------------------------------------------------------------------------------------

// WriteNode 把 msg.Data 的点位值列表写入三菱 PLC，成功走 Success 链。
//
// 输入(msg.Data)：[{"name","addr","type","value"}]，value 支持 ${msg.xx}
type WriteNode struct {
	base.SharedNode[*gomcprotocol.Client3E]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *WriteNode) Type() string {
	return "x/mcWrite"
}

// New 默认配置
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:6000",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "D100", Type: "UINT16", Value: "${msg.value}"},
			},
		},
	}
}

// Init 初始化
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gomcprotocol.Client3E, error) {
		return newClient(x.Config)
	}, func(client *gomcprotocol.Client3E) error {
		if client != nil {
			return client.Close()
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
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no mc points: configure points or pass [{...}] via msg.Data"))
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
			opLock := mcOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client).WritePoints(rendered)
		}()
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
			mcOpLocks.Delete(oldClient)
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接（语义同 ReadNode.reconnect）
func (x *WriteNode) reconnect(old *gomcprotocol.Client3E) (*gomcprotocol.Client3E, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(mcReconnecter); ok {
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("mc ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	client, err := newClient(x.Config)
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(client)
	return client, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[MC] "+format, v...)
	}
}

// Destroy 清理资源
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			mcOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *WriteNode) Desc() string {
	return "Mitsubishi MC protocol client for writing PLC points. Routes to Success/Failure"
}
