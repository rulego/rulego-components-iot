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

// Package modbus_server 提供 Modbus TCP 从站端点：监听 TCP 端口接受主站连接，
// 主站写 Coil/Holding Register 时触发消息流入规则链处理。
package modbus_server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/textproto"
	"sync"
	"time"

	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/utils/maps"
	"github.com/simonvetter/modbus"
)

const Type = types.EndpointTypePrefix + "modbusServer"
const ModbusWriteMsgType = "MODBUS_WRITE"

// 注册端点
func init() {
	_ = endpoint.Registry.Register(&Endpoint{})
}

// Endpoint 别名
type Endpoint = ModbusServerEndpoint

var _ endpointApi.Endpoint = (*Endpoint)(nil)

// RequestMessage 写触发消息
type RequestMessage struct {
	headers textproto.MIMEHeader
	body    []byte
	msg     *types.RuleMsg
	from    string
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
		ruleMsg := types.NewMsg(0, ModbusWriteMsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *RequestMessage) SetStatusCode(c int) {}
func (r *RequestMessage) SetBody(b []byte)    { r.body = b }
func (r *RequestMessage) SetError(err error)  {}
func (r *RequestMessage) GetError() error     { return nil }

// ResponseMessage 占位（从站端点不主动响应）
type ResponseMessage struct {
	headers textproto.MIMEHeader
	body    []byte
	msg     *types.RuleMsg
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
		ruleMsg := types.NewMsg(0, ModbusWriteMsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *ResponseMessage) SetStatusCode(c int) {}
func (r *ResponseMessage) SetBody(b []byte)    { r.body = b }
func (r *ResponseMessage) SetError(err error)  {}
func (r *ResponseMessage) GetError() error     { return nil }

// Config Modbus 从站端点配置
type Config struct {
	// 监听地址，格式 tcp://host:port，如 tcp://:502
	Server string `json:"server" label:"Server" desc:"listen URL, e.g. tcp://:502" required:"true" ref:"primary"`
	// 从站地址(Unit ID)，0 表示接受所有
	UnitId int `json:"unitId" label:"Unit ID" desc:"slave unit ID, 0 = accept all"`
	// 最大并发客户端连接数，默认 10
	MaxClients uint `json:"maxClients" label:"Max Clients" desc:"max concurrent client connections, default 10"`
	// Coil 区大小（位），默认 2000
	Coils uint `json:"coils" label:"Coils" desc:"coil register count, default 2000"`
	// 寄存器区大小（字），默认 2000
	Registers uint `json:"registers" label:"Registers" desc:"register count, default 2000"`
}

// ModbusServerEndpoint Modbus TCP 从站端点
type ModbusServerEndpoint struct {
	impl.BaseEndpoint
	base.GracefulShutdown
	RuleConfig types.Config
	Config     Config
	Router     endpointApi.Router
	server     *modbus.ModbusServer
	handler    *registerHandler
	ctx        context.Context
	cancel     context.CancelFunc
}

// Type 组件类型
func (x *ModbusServerEndpoint) Type() string { return Type }

// New 创建组件实例
func (x *ModbusServerEndpoint) New() types.Node {
	return &ModbusServerEndpoint{
		Config: Config{
			Server:     "tcp://:502",
			MaxClients: 10,
			Coils:      2000,
			Registers:  2000,
		},
	}
}

// Init 初始化
func (x *ModbusServerEndpoint) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	x.GracefulShutdown.InitGracefulShutdown(x.RuleConfig.Logger, 10*time.Second)
	x.ctx, x.cancel = context.WithCancel(context.Background())
	if x.Config.Coils == 0 {
		x.Config.Coils = 2000
	}
	if x.Config.Registers == 0 {
		x.Config.Registers = 2000
	}
	if x.Config.MaxClients == 0 {
		x.Config.MaxClients = 10
	}
	x.handler = &registerHandler{
		endpoint: x,
		coils:    make([]bool, x.Config.Coils),
		hr:       make([]uint16, x.Config.Registers),
		ir:       make([]uint16, x.Config.Registers),
		di:       make([]bool, x.Config.Coils),
	}
	return err
}

// Destroy 销毁
func (x *ModbusServerEndpoint) Destroy() {
	x.GracefulShutdown.GracefulStop(func() {
		x.Close()
	})
}

// Desc 组件描述
func (x *ModbusServerEndpoint) Desc() string {
	return "Modbus TCP slave endpoint. Accepts master connections; writes trigger rule chain messages"
}

// Category 组件分类
func (x *ModbusServerEndpoint) Category() string { return "endpoint" }

// Def 组件定义
func (x *ModbusServerEndpoint) Def() types.ComponentForm {
	return types.ComponentForm{
		Desc:       x.Desc(),
		RouterForm: &types.RouterForm{Hide: true},
	}
}

// Id 返回端点 ID
func (x *ModbusServerEndpoint) Id() string { return x.Config.Server }

// Close 停止服务器
func (x *ModbusServerEndpoint) Close() error {
	if x.server != nil {
		_ = x.server.Stop()
	}
	if x.cancel != nil {
		x.cancel()
	}
	return nil
}

// AddRouter 添加路由（单路由）
func (x *ModbusServerEndpoint) AddRouter(router endpointApi.Router, params ...interface{}) (string, error) {
	if router == nil {
		return "", errors.New("router cannot be nil")
	}
	if x.Router != nil {
		return "", errors.New("modbus server endpoint only supports one router")
	}
	if len(params) > 0 {
		router.SetParams(params...)
	}
	x.CheckAndSetRouterId(router)
	x.Router = router
	return router.GetId(), nil
}

// RemoveRouter 移除路由
func (x *ModbusServerEndpoint) RemoveRouter(routerId string, params ...interface{}) error {
	x.Router = nil
	return nil
}

// Start 启动 Modbus TCP 从站
func (x *ModbusServerEndpoint) Start() error {
	var err error
	x.server, err = modbus.NewServer(&modbus.ServerConfiguration{
		URL:        x.Config.Server,
		Timeout:    60 * time.Second,
		MaxClients: x.Config.MaxClients,
	}, x.handler)
	if err != nil {
		return err
	}
	return x.server.Start()
}

// SetRegisters 外部写入寄存器值（规则链处理后回写，供主站读取）
func (x *ModbusServerEndpoint) SetRegisters(addr uint16, values []uint16) {
	x.handler.lock.Lock()
	defer x.handler.lock.Unlock()
	for i, v := range values {
		idx := int(addr) + i
		if idx < len(x.handler.hr) {
			x.handler.hr[idx] = v
		}
	}
}

// SetCoils 外部写入 Coil 值
func (x *ModbusServerEndpoint) SetCoils(addr uint16, values []bool) {
	x.handler.lock.Lock()
	defer x.handler.lock.Unlock()
	for i, v := range values {
		idx := int(addr) + i
		if idx < len(x.handler.coils) {
			x.handler.coils[idx] = v
		}
	}
}

// Printf 日志
func (x *ModbusServerEndpoint) Printf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Printf(format, v...)
	}
}

// --- registerHandler 实现 modbus.RequestHandler ---

type registerHandler struct {
	endpoint *ModbusServerEndpoint
	lock     sync.RWMutex
	coils    []bool
	di       []bool
	hr       []uint16
	ir       []uint16
}

var _ modbus.RequestHandler = (*registerHandler)(nil)

func (h *registerHandler) checkUnitId(unitId uint8) error {
	cfgUnit := h.endpoint.Config.UnitId
	if cfgUnit != 0 && int(unitId) != cfgUnit {
		return modbus.ErrIllegalFunction
	}
	return nil
}

func (h *registerHandler) HandleCoils(req *modbus.CoilsRequest) ([]bool, error) {
	if err := h.checkUnitId(req.UnitId); err != nil {
		return nil, err
	}
	if int(req.Addr)+int(req.Quantity) > len(h.coils) {
		return nil, modbus.ErrIllegalDataAddress
	}
	h.lock.Lock()
	defer h.lock.Unlock()
	res := make([]bool, req.Quantity)
	for i := 0; i < int(req.Quantity); i++ {
		if req.IsWrite {
			h.coils[int(req.Addr)+i] = req.Args[i]
		}
		res[i] = h.coils[int(req.Addr)+i]
	}
	if req.IsWrite {
		go h.endpoint.onWrite("coil", req.ClientAddr, req.UnitId, req.Addr, req.Quantity, boolsToAny(req.Args))
	}
	return res, nil
}

func (h *registerHandler) HandleDiscreteInputs(req *modbus.DiscreteInputsRequest) ([]bool, error) {
	if err := h.checkUnitId(req.UnitId); err != nil {
		return nil, err
	}
	if int(req.Addr)+int(req.Quantity) > len(h.di) {
		return nil, modbus.ErrIllegalDataAddress
	}
	h.lock.RLock()
	defer h.lock.RUnlock()
	res := make([]bool, req.Quantity)
	for i := 0; i < int(req.Quantity); i++ {
		res[i] = h.di[int(req.Addr)+i]
	}
	return res, nil
}

func (h *registerHandler) HandleHoldingRegisters(req *modbus.HoldingRegistersRequest) ([]uint16, error) {
	if err := h.checkUnitId(req.UnitId); err != nil {
		return nil, err
	}
	if int(req.Addr)+int(req.Quantity) > len(h.hr) {
		return nil, modbus.ErrIllegalDataAddress
	}
	h.lock.Lock()
	defer h.lock.Unlock()
	res := make([]uint16, req.Quantity)
	for i := 0; i < int(req.Quantity); i++ {
		if req.IsWrite {
			h.hr[int(req.Addr)+i] = req.Args[i]
		}
		res[i] = h.hr[int(req.Addr)+i]
	}
	if req.IsWrite {
		go h.endpoint.onWrite("holding_register", req.ClientAddr, req.UnitId, req.Addr, req.Quantity, uint16sToAny(req.Args))
	}
	return res, nil
}

func (h *registerHandler) HandleInputRegisters(req *modbus.InputRegistersRequest) ([]uint16, error) {
	if err := h.checkUnitId(req.UnitId); err != nil {
		return nil, err
	}
	if int(req.Addr)+int(req.Quantity) > len(h.ir) {
		return nil, modbus.ErrIllegalDataAddress
	}
	h.lock.RLock()
	defer h.lock.RUnlock()
	res := make([]uint16, req.Quantity)
	for i := 0; i < int(req.Quantity); i++ {
		res[i] = h.ir[int(req.Addr)+i]
	}
	return res, nil
}

// onWrite 写触发：构造消息注入规则链
func (x *ModbusServerEndpoint) onWrite(regType, clientAddr string, unitId uint8, addr, quantity uint16, values []interface{}) {
	x.GracefulShutdown.IncrementActiveOperations()
	defer x.GracefulShutdown.DecrementActiveOperations()

	if x.Router == nil {
		return
	}
	payload := map[string]interface{}{
		"type":       regType,
		"unitId":     unitId,
		"addr":       addr,
		"modbusAddr": modiconAddr(regType, addr),
		"quantity":   quantity,
		"values":     values,
		"clientAddr": clientAddr,
		"timestamp":  time.Now().UnixNano(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	exchange := &endpointApi.Exchange{
		In:  &RequestMessage{from: clientAddr, body: b},
		Out: &ResponseMessage{},
	}
	md := exchange.In.GetMsg().Metadata
	md.PutValue("modbusType", regType)
	md.PutValue("clientAddr", clientAddr)
	x.DoProcess(x.ctx, x.Router, exchange)
}

// modiconAddr 把 PDU 地址按寄存器区段换算成 Modicon 友好地址（5 位字符串）。
func modiconAddr(regType string, addr uint16) string {
	base := 1
	switch regType {
	case "holding_register":
		base = 40001
	case "input_register":
		base = 30001
	case "discrete_input":
		base = 10001
	}
	return fmt.Sprintf("%05d", base+int(addr))
}

func boolsToAny(vals []bool) []interface{} {
	out := make([]interface{}, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}

func uint16sToAny(vals []uint16) []interface{} {
	out := make([]interface{}, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}
