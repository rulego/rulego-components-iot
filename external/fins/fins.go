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

// Package fins 提供欧姆龙 FINS 协议 PLC(CJ/CP/NJ/NX 系列)的读取(ReadNode)与写入(WriteNode)节点。
//
// 用法：
//   - 定时采集：前置 endpoint/schedule，点位在下方 points 配置。
//   - 按需读/写：msg.Data 带点位列表则优先使用（动态场景）。
//
// 点位字段均支持 ${msg.xx} / ${metadata.xx} 模板变量。
package fins

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rulego/rulego"
	finsclient "github.com/rulego/rulego-components-iot/pkg/fins_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// defaultFinsPort FINS 默认端口(UDP 与 TCP 均为 9600)
const defaultFinsPort = 9600

// 注册节点
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// Configuration 连接配置（读/写节点共用）
type Configuration struct {
	// PLC 地址，格式 IP 或 IP:port，FINS 默认端口 9600
	Server string `json:"server" label:"Server" desc:"PLC IP[:port], FINS default port 9600" required:"true" ref:"primary"`
	// 传输方式：udp(默认) 或 tcp(FINS/TCP，含节点地址协商)
	Transport string `json:"transport" label:"Transport" desc:"transport: udp (default) or tcp (FINS/TCP with node handshake)"`
	// FINS 网络号(DA1/SA1)，默认 0
	Network int `json:"network" label:"Network" desc:"FINS network number (DA1/SA1), default 0"`
	// 目标节点号(DA2)，即 PLC 的 FINS 节点号，默认 0
	DstNode int `json:"dstNode" label:"Dest Node" desc:"destination FINS node number (DA2), default 0"`
	// 源节点号(SA2)，即本客户端的 FINS 节点号，默认 0
	SrcNode int `json:"srcNode" label:"Source Node" desc:"source FINS node number (SA2), default 0"`
	// 单元地址(DA3)，CPU 单元号，默认 0
	Unit int `json:"unit" label:"Unit" desc:"unit address (DA3), default 0"`
	// 请求超时(秒)，默认 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// 默认点位表。定时采集(schedule 触发)时使用；msg.Data 带点位则优先
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// initClient 建立 FINS 客户端(UDP 默认；transport=tcp 走 FINS/TCP 并自动握手)。
func (c Configuration) initClient() (*finsclient.Client, error) {
	host, portStr, err := net.SplitHostPort(c.Server)
	if err != nil {
		host = c.Server
		portStr = strconv.Itoa(defaultFinsPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("fins server %q: invalid port", c.Server)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	local := finsclient.NewAddress("0.0.0.0", 0, byte(c.Network), byte(c.SrcNode), 0)
	plc := finsclient.NewAddress(host, port, byte(c.Network), byte(c.DstNode), byte(c.Unit))
	opts := []finsclient.Option{finsclient.WithTimeout(time.Duration(timeout) * time.Second)}
	switch strings.ToLower(strings.TrimSpace(c.Transport)) {
	case "", "udp":
	case "tcp":
		opts = append(opts, finsclient.WithTCP())
	default:
		return nil, fmt.Errorf("fins transport %q: expect udp or tcp", c.Transport)
	}
	return finsclient.NewClient(local, plc, opts...)
}

// finsOpLocks 按底层 client 关联操作锁，串行化共享 client 的并发读写。
var finsOpLocks iot_points.OpLocks

// finsReconnecter 连接重建能力接口。
type finsReconnecter interface {
	reconnect(old *finsclient.Client) (*finsclient.Client, error)
}

// ------------------------------------------------------------------------------------------------
// ReadNode FINS 读节点
// ------------------------------------------------------------------------------------------------

// ReadNode 批量读取 FINS 点位，结果(统一契约 Data 列表)写回 msg.Data，经 Success 链转出。
//
// 输入(msg.Data 可选)：点位列表 JSON，格式同 points 配置。空则用配置的 points。
// 输出(msg.Data)：[{"name","value","timestamp","error"}]（timestamp 为 ns；error 仅单点失败时存在）
type ReadNode struct {
	base.SharedNode[*finsclient.Client]
	Config Configuration
	// reconnectLocker 保护重连
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *ReadNode) Type() string {
	return "x/finsRead"
}

// New 默认配置
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:9600",
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*finsclient.Client, error) {
		return x.Config.initClient()
	}, func(client *finsclient.Client) error {
		if client != nil {
			client.Close()
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
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no fins points: configure points or pass [{...}] via msg.Data"))
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
			opLock := finsOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client).ReadPoints(rendered)
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
			finsOpLocks.Delete(oldClient) // 清理旧连接操作锁
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接。
func (x *ReadNode) reconnect(old *finsclient.Client) (*finsclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(finsReconnecter); ok { // 跨类型：Read↔Write 均可委派
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("fins ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		old.Close()
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := x.Config.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[FINS] "+format, v...)
	}
}

// Destroy 清理资源
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // 仅 owner 清理操作锁
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			finsOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *ReadNode) Desc() string {
	return "Omron FINS client for batch reading PLC points. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode FINS 写节点
// ------------------------------------------------------------------------------------------------

// WriteNode 把 msg.Data 的点位值列表写入 FINS PLC，成功走 Success 链。
//
// 输入(msg.Data)：[{"name","addr","type","value"}]，value 支持 ${msg.xx}
type WriteNode struct {
	base.SharedNode[*finsclient.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type 返回组件类型
func (x *WriteNode) Type() string {
	return "x/finsWrite"
}

// New 默认配置
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:9600",
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*finsclient.Client, error) {
		return x.Config.initClient()
	}, func(client *finsclient.Client) error {
		if client != nil {
			client.Close()
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
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no fins points: configure points or pass [{...}] via msg.Data"))
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
			opLock := finsOpLocks.Lock(client)
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
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, lastErr)
			oldClient := client
			newClient, rerr := x.reconnect(oldClient)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			finsOpLocks.Delete(oldClient) // 清理旧连接操作锁
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect 安全重建连接（语义同 ReadNode.reconnect）
func (x *WriteNode) reconnect(old *finsclient.Client) (*finsclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(finsReconnecter); ok { // 跨类型：Read↔Write 均可委派
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("fins ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		old.Close()
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := x.Config.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[FINS] "+format, v...)
	}
}

// Destroy 清理资源
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			finsOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc 组件描述
func (x *WriteNode) Desc() string {
	return "Omron FINS client for writing PLC points. Routes to Success/Failure"
}
