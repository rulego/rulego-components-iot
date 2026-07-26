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

// Package snmp 提供 SNMP Trap 接收端点：监听 UDP 162，接收设备主动推送的
// Trap/Inform 告警，转成消息流入规则链处理。
package snmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/utils/maps"
)

const Type = types.EndpointTypePrefix + "snmp"
const SNMPTrapMsgType = "SNMP_TRAP"

// Trap 注入 msg.Metadata 的 key，下游用 ${metadata.xx} 取值
const (
	MetadataKeyFrom      = "from"
	MetadataKeyCommunity = "community"
	MetadataKeyVersion   = "version"
	MetadataKeyTrapOID   = "trapOID"
)

// Endpoint 别名
type Endpoint = SnmpTrapEndpoint

var _ endpointApi.Endpoint = (*Endpoint)(nil)

// 注册端点
func init() {
	_ = endpoint.Registry.Register(&Endpoint{})
}

// RequestMessage 包装 Trap 数据
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
		ruleMsg := types.NewMsg(0, SNMPTrapMsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *RequestMessage) SetStatusCode(c int) { r.statusCode = c }
func (r *RequestMessage) SetBody(b []byte)    { r.body = b }
func (r *RequestMessage) SetError(err error)  { r.err = err }
func (r *RequestMessage) GetError() error     { return r.err }

// ResponseMessage 响应消息（Trap 接收端不使用，占位满足接口）
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
		ruleMsg := types.NewMsg(0, SNMPTrapMsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *ResponseMessage) SetStatusCode(c int) { r.statusCode = c }
func (r *ResponseMessage) SetBody(b []byte)    { r.body = b }
func (r *ResponseMessage) SetError(err error)  { r.err = err }
func (r *ResponseMessage) GetError() error     { return r.err }

// SnmpTrapConfig Trap 端点配置
type SnmpTrapConfig struct {
	// 监听地址，默认 0.0.0.0:162（162 是特权端口，Linux 需 root 或 setcap）
	Server string `json:"server" label:"Server" desc:"listen address, e.g. 0.0.0.0:162 (port 162 needs root/setcap on linux)" required:"true" ref:"primary"`
	// SNMP 版本（Trap 解码用），v1/v2c/v3，默认 v2c
	Version string `json:"version" label:"Version" desc:"v1/v2c/v3, default v2c"`
	// community（v1/v2c Trap 校验）
	Community string `json:"community" label:"Community" desc:"community string for v1/v2c"`
}

// SnmpTrapEndpoint SNMP Trap 接收端点
type SnmpTrapEndpoint struct {
	impl.BaseEndpoint
	// GracefulShutdown 优雅停机
	base.GracefulShutdown
	RuleConfig types.Config
	Config     SnmpTrapConfig
	// 路由（单路由，Trap 无路径区分）
	Router endpointApi.Router
	// Trap 监听器
	listener   *gosnmp.TrapListener
	trapCtx    context.Context
	trapCancel context.CancelFunc
	listenerWg sync.WaitGroup
}

// Type 组件类型
func (x *SnmpTrapEndpoint) Type() string { return Type }

// New 创建组件实例
func (x *SnmpTrapEndpoint) New() types.Node {
	return &SnmpTrapEndpoint{
		Config: SnmpTrapConfig{
			Server:    "0.0.0.0:162",
			Version:   "v2c",
			Community: "public",
		},
	}
}

// Init 初始化
func (x *SnmpTrapEndpoint) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	x.GracefulShutdown.InitGracefulShutdown(x.RuleConfig.Logger, 10*time.Second)
	x.trapCtx, x.trapCancel = context.WithCancel(context.Background())
	return err
}

// Destroy 销毁
func (x *SnmpTrapEndpoint) Destroy() {
	x.GracefulShutdown.GracefulStop(func() {
		x.Close()
	})
}

// Desc 组件描述
func (x *SnmpTrapEndpoint) Desc() string {
	return "SNMP Trap receiver endpoint. Listens on UDP 162 for device Trap/Inform alerts"
}

// Category 组件分类
func (x *SnmpTrapEndpoint) Category() string { return "endpoint" }

// Def 组件定义
func (x *SnmpTrapEndpoint) Def() types.ComponentForm {
	return types.ComponentForm{
		Desc: "SNMP Trap receiver endpoint. Listens on UDP 162 for device Trap/Inform alerts",
		RouterForm: &types.RouterForm{
			Hide: true,
		},
	}
}

// Close 关闭监听
func (x *SnmpTrapEndpoint) Close() error {
	if x.listener != nil {
		x.listener.Close()
	}
	x.listenerWg.Wait()
	if x.trapCancel != nil {
		x.trapCancel()
	}
	return nil
}

// Id 返回端点 ID
func (x *SnmpTrapEndpoint) Id() string { return x.Config.Server }

// AddRouter 添加路由（单路由，Trap 无路径区分）
func (x *SnmpTrapEndpoint) AddRouter(router endpointApi.Router, params ...interface{}) (string, error) {
	if router == nil {
		return "", errors.New("router cannot be nil")
	}
	if x.Router != nil {
		return "", errors.New("snmp trap endpoint only supports one router")
	}
	if len(params) > 0 {
		router.SetParams(params...)
	}
	x.CheckAndSetRouterId(router)
	x.Router = router
	return router.GetId(), nil
}

// RemoveRouter 移除路由
func (x *SnmpTrapEndpoint) RemoveRouter(routerId string, params ...interface{}) error {
	x.Router = nil
	return nil
}

// Start 启动 Trap 监听
func (x *SnmpTrapEndpoint) Start() error {
	version, err := parseVersion(x.Config.Version)
	if err != nil {
		return err
	}
	x.listener = gosnmp.NewTrapListener()
	x.listener.Params = &gosnmp.GoSNMP{
		Port:      162,
		Community: x.Config.Community,
		Version:   version,
		Logger:    gosnmp.NewLogger(log.New(io.Discard, "", 0)),
	}
	x.listener.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		x.handleTrap(packet, addr)
	}
	x.listenerWg.Add(1)
	go func() {
		defer x.listenerWg.Done()
		if err := x.listener.Listen(x.Config.Server); err != nil {
			x.Printf("snmp trap listen error: %v", err)
		}
	}()
	return nil
}

// handleTrap 处理收到的 Trap：转成消息流入规则链
func (x *SnmpTrapEndpoint) handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	x.GracefulShutdown.IncrementActiveOperations()
	defer x.GracefulShutdown.DecrementActiveOperations()

	if x.Router == nil {
		return
	}
	payload := map[string]interface{}{
		"from":      addr.String(),
		"version":   versionString(packet.Version),
		"community": packet.Community,
		"timestamp": packet.Timestamp,
		"variables": trapVars(packet.Variables),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		x.Printf("marshal trap error: %v", err)
		return
	}
	exchange := &endpointApi.Exchange{
		In:  &RequestMessage{from: addr.String(), body: b},
		Out: &ResponseMessage{},
	}
	md := exchange.In.GetMsg().Metadata
	md.PutValue(MetadataKeyFrom, addr.String())
	md.PutValue(MetadataKeyCommunity, packet.Community)
	md.PutValue(MetadataKeyVersion, versionString(packet.Version))
	if oid := snmpTrapOID(packet.Variables); oid != "" {
		md.PutValue(MetadataKeyTrapOID, oid)
	}
	x.DoProcess(x.trapCtx, x.Router, exchange)
}

// snmpTrapOID 提取 Trap 的 snmpTrapOID（1.3.6.1.6.3.1.1.4.1.0）值
func snmpTrapOID(vars []gosnmp.SnmpPDU) string {
	for _, v := range vars {
		if strings.TrimPrefix(v.Name, ".") == "1.3.6.1.6.3.1.1.4.1.0" {
			if s, ok := v.Value.(string); ok {
				return strings.TrimPrefix(s, ".")
			}
		}
	}
	return ""
}

// trapVars PDU 列表 -> 简化 map
func trapVars(vars []gosnmp.SnmpPDU) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(vars))
	for _, v := range vars {
		out = append(out, map[string]interface{}{
			"oid":   v.Name,
			"value": v.Value,
			"type":  pduTypeString(v.Type),
		})
	}
	return out
}

// pduTypeString PDU 类型 -> 字符串
func pduTypeString(t gosnmp.Asn1BER) string {
	switch t {
	case gosnmp.Integer:
		return "Integer"
	case gosnmp.OctetString:
		return "OctetString"
	case gosnmp.ObjectIdentifier:
		return "ObjectIdentifier"
	case gosnmp.IPAddress:
		return "IPAddress"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.TimeTicks:
		return "TimeTicks"
	case gosnmp.Counter64:
		return "Counter64"
	case gosnmp.Null:
		return "Null"
	}
	return "Unknown"
}

func versionString(v gosnmp.SnmpVersion) string {
	switch v {
	case gosnmp.Version1:
		return "v1"
	case gosnmp.Version2c:
		return "v2c"
	case gosnmp.Version3:
		return "v3"
	}
	return "unknown"
}

// parseVersion 版本字符串 -> gosnmp.SnmpVersion
func parseVersion(s string) (gosnmp.SnmpVersion, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "v2c", "v2", "2c":
		return gosnmp.Version2c, nil
	case "v1", "1":
		return gosnmp.Version1, nil
	case "v3", "3":
		return gosnmp.Version3, nil
	}
	return 0, fmt.Errorf("unsupported snmp version: %q", s)
}

// Printf 日志
func (x *SnmpTrapEndpoint) Printf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Printf(format, v...)
	}
}
