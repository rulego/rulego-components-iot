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

// Package hj212 提供 HJ212（HJ 212-2017 污染物在线监控数据传输标准）被动接收端点：
// 监听 TCP 端口，接收设备主动上报的帧，解析污染物因子为统一 iot_points.Data 流入规则链。
// 仅做被动采集，不主动应答设备（Flag bit0 应答由下游规则自行处理）。
package hj212

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/textproto"
	"strconv"
	"sync"
	"time"

	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/utils/maps"
)

const Type = types.EndpointTypePrefix + "hj212"
const HJ212MsgType = "HJ212"

// 帧字段注入 msg.Metadata 的 key，下游用 ${metadata.xx} 取值
const (
	MetadataKeyFrom     = "from"
	MetadataKeyMN       = "mn"
	MetadataKeyST       = "st"
	MetadataKeyCN       = "cn"
	MetadataKeyDataTime = "dataTime"
)

// Endpoint 别名
type Endpoint = HJ212Endpoint

var _ endpointApi.Endpoint = (*Endpoint)(nil)

// 注册端点
func init() {
	_ = endpoint.Registry.Register(&Endpoint{})
}

// RequestMessage 包装一帧解析出的点位数据
type RequestMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	msg        *types.RuleMsg
	from       string
	statusCode int
	err        error
}

func (r *RequestMessage) Body() []byte { return r.body }
func (r *RequestMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}
func (r *RequestMessage) From() string               { return r.from }
func (r *RequestMessage) GetParam(key string) string { return "" }
func (r *RequestMessage) SetMsg(msg *types.RuleMsg)  { r.msg = msg }
func (r *RequestMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		ruleMsg := types.NewMsg(0, HJ212MsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *RequestMessage) SetStatusCode(c int) { r.statusCode = c }
func (r *RequestMessage) SetBody(b []byte)    { r.body = b }
func (r *RequestMessage) SetError(err error)  { r.err = err }
func (r *RequestMessage) GetError() error     { return r.err }

// ResponseMessage 响应消息（被动接收端不使用，占位满足接口）
type ResponseMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	msg        *types.RuleMsg
	statusCode int
	err        error
}

func (r *ResponseMessage) Body() []byte { return r.body }
func (r *ResponseMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}
func (r *ResponseMessage) From() string               { return "" }
func (r *ResponseMessage) GetParam(key string) string { return "" }
func (r *ResponseMessage) SetMsg(msg *types.RuleMsg)  { r.msg = msg }
func (r *ResponseMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		ruleMsg := types.NewMsg(0, HJ212MsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *ResponseMessage) SetStatusCode(c int) { r.statusCode = c }
func (r *ResponseMessage) SetBody(b []byte)    { r.body = b }
func (r *ResponseMessage) SetError(err error)  { r.err = err }
func (r *ResponseMessage) GetError() error     { return r.err }

// HJ212Config HJ212 端点配置
type HJ212Config struct {
	// 监听地址，默认 0.0.0.0:8005
	Server string `json:"server" label:"Server" desc:"listen address, e.g. 0.0.0.0:8005" required:"true" ref:"primary"`
}

// HJ212Endpoint HJ212 被动接收端点
type HJ212Endpoint struct {
	impl.BaseEndpoint
	// GracefulShutdown 优雅停机
	base.GracefulShutdown
	RuleConfig types.Config
	Config     HJ212Config
	// 路由（单路由，上报数据无路径区分）
	Router   endpointApi.Router
	listener net.Listener
	connCtx  context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// Type 组件类型
func (x *HJ212Endpoint) Type() string { return Type }

// New 创建组件实例
func (x *HJ212Endpoint) New() types.Node {
	return &HJ212Endpoint{
		Config: HJ212Config{
			Server: "0.0.0.0:8005",
		},
	}
}

// Init 初始化
func (x *HJ212Endpoint) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	x.GracefulShutdown.InitGracefulShutdown(x.RuleConfig.Logger, 10*time.Second)
	x.connCtx, x.cancel = context.WithCancel(context.Background())
	return err
}

// Destroy 销毁
func (x *HJ212Endpoint) Destroy() {
	x.GracefulShutdown.GracefulStop(func() {
		_ = x.Close()
	})
}

// Desc 组件描述
func (x *HJ212Endpoint) Desc() string {
	return "HJ212 receiver endpoint. Listens on TCP port for pollution source monitoring devices to report data (HJ 212-2017)"
}

// Category 组件分类
func (x *HJ212Endpoint) Category() string { return "endpoint" }

// Def 组件定义
func (x *HJ212Endpoint) Def() types.ComponentForm {
	return types.ComponentForm{
		Desc: "HJ212 receiver endpoint. Listens on TCP port for pollution source monitoring devices to report data (HJ 212-2017)",
		RouterForm: &types.RouterForm{
			Hide: true,
		},
	}
}

// Close 关闭监听
func (x *HJ212Endpoint) Close() error {
	if x.cancel != nil {
		x.cancel()
	}
	if x.listener != nil {
		_ = x.listener.Close()
	}
	x.wg.Wait()
	return nil
}

// Id 返回端点 ID
func (x *HJ212Endpoint) Id() string { return x.Config.Server }

// AddRouter 添加路由（单路由，上报数据无路径区分）
func (x *HJ212Endpoint) AddRouter(router endpointApi.Router, params ...interface{}) (string, error) {
	if router == nil {
		return "", errors.New("router cannot be nil")
	}
	if x.Router != nil {
		return "", errors.New("hj212 endpoint only supports one router")
	}
	if len(params) > 0 {
		router.SetParams(params...)
	}
	x.CheckAndSetRouterId(router)
	x.Router = router
	return router.GetId(), nil
}

// RemoveRouter 移除路由
func (x *HJ212Endpoint) RemoveRouter(routerId string, params ...interface{}) error {
	x.Router = nil
	return nil
}

// Start 启动 TCP 监听
func (x *HJ212Endpoint) Start() error {
	listener, err := net.Listen("tcp", x.Config.Server)
	if err != nil {
		return err
	}
	x.listener = listener
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			x.wg.Add(1)
			go func() {
				defer x.wg.Done()
				x.handleConn(conn)
			}()
		}
	}()
	return nil
}

// handleConn 读取连接流，按 ##+长度 边界切帧并解析
func (x *HJ212Endpoint) handleConn(conn net.Conn) {
	defer conn.Close()
	x.GracefulShutdown.IncrementActiveOperations()
	defer x.GracefulShutdown.DecrementActiveOperations()
	addr := conn.RemoteAddr().String()
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 1024)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxDataLen+12 { // 超限保护：丢弃缓冲
				x.Printf("hj212: buffer overflow from %s, drop connection data", addr)
				buf = buf[:0]
			}
			for {
				frame, used, ok := extractFrame(buf)
				if used > 0 && !ok {
					buf = buf[used:]
					continue
				}
				if !ok {
					break
				}
				x.handleFrame(conn, addr, frame)
				buf = buf[used:]
			}
		}
		if err != nil {
			return
		}
	}
}

// handleFrame 解析一帧，Flag bit0=1 时回写 ACK，点位列表转消息流入规则链
func (x *HJ212Endpoint) handleFrame(conn net.Conn, from string, raw []byte) {
	frame, err := ParseFrame(raw)
	if err != nil {
		x.Printf("hj212 parse error from %s: %v", from, err)
		return
	}
	// Flag bit0=1 表示设备要求应答，立即回写确认帧
	if flagVal, ferr := strconv.Atoi(frame.Flag); ferr == nil && flagVal&0x01 != 0 {
		ack := BuildAckFrame(frame)
		if _, werr := conn.Write(ack); werr != nil {
			x.Printf("hj212 write ack to %s error: %v", from, werr)
		}
	}
	if x.Router == nil {
		return
	}
	b, err := json.Marshal(frame.Points)
	if err != nil {
		x.Printf("hj212 marshal points error: %v", err)
		return
	}
	exchange := &endpointApi.Exchange{
		In:  &RequestMessage{from: from, body: b},
		Out: &ResponseMessage{},
	}
	md := exchange.In.GetMsg().Metadata
	md.PutValue(MetadataKeyFrom, from)
	md.PutValue(MetadataKeyMN, frame.MN)
	md.PutValue(MetadataKeyST, frame.ST)
	md.PutValue(MetadataKeyCN, frame.CN)
	if !frame.DataTime.IsZero() {
		md.PutValue(MetadataKeyDataTime, frame.DataTime.Format("2006-01-02 15:04:05"))
	}
	x.DoProcess(x.connCtx, x.Router, exchange)
}

// Printf 日志
func (x *HJ212Endpoint) Printf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Printf(format, v...)
	}
}
