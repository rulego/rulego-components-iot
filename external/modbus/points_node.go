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

package modbus

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
	"github.com/simonvetter/modbus"
)

// 注册节点
func init() {
	_ = rulego.Registry.Register(&ReadPointsNode{})
	_ = rulego.Registry.Register(&WritePointsNode{})
}

// modbusPointsReconnecter 连接重建能力接口。
type modbusPointsReconnecter interface {
	reconnect(old *modbus.ModbusClient) (*modbus.ModbusClient, error)
}

// PointsConfiguration 点位式 modbus 节点配置（读/写共用）。
type PointsConfiguration struct {
	// 服务器地址，格式 tcp://host:port 或 rtu:///dev/ttyUSB0
	Server string `json:"server" label:"Server" desc:"Modbus server address, format: tcp://host:port or rtu:///dev/ttyUSB0" required:"true" ref:"primary"`
	// UnitId 从机编号
	UnitId uint8 `json:"unitId" label:"Unit ID" desc:"Modbus slave unit ID"`
	// 默认点位表（addr=Modicon 地址如 40001；为空则从 msg.Data 解析点位）
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points; addr=Modicon e.g. 40001; empty=parse from msg.Data"`
	// TCP 连接配置
	TcpConfig TcpConfig `json:"tcpConfig" label:"TCP Config" desc:"TCP connection configuration"`
	// RTU 串口配置
	RtuConfig RtuConfig `json:"rtuConfig" label:"RTU Config" desc:"RTU serial configuration"`
	// 数据编码（多寄存器字节序/字序）
	EncodingConfig EncodingConfig `json:"encodingConfig" label:"Encoding Config" desc:"Data encoding configuration"`
}

// modbusConn 连接管理（read/write 节点共用）。
type modbusConn struct {
	base.SharedNode[*modbus.ModbusClient]
	Config          PointsConfiguration
	reconnectLocker sync.Mutex
	currentUnitId   uint8
	currentUnitIdMu sync.RWMutex
}

func (x *modbusConn) getCurrentUnitId() uint8 {
	x.currentUnitIdMu.RLock()
	defer x.currentUnitIdMu.RUnlock()
	return x.currentUnitId
}

func (x *modbusConn) setUnitId(client *modbus.ModbusClient, unitId uint8) {
	x.currentUnitIdMu.Lock()
	defer x.currentUnitIdMu.Unlock()
	x.currentUnitId = unitId
	if client != nil {
		client.SetUnitId(unitId)
	}
}

// newRetryableClient 为本次请求创建带重试/重连的客户端封装。
func (x *modbusConn) newRetryableClient(client *modbus.ModbusClient) *RetryableModbusClient {
	return NewRetryableModbusClient(
		client, 3, x.RuleConfig.Logger, x.reconnect,
		x.getCurrentUnitId(),
		modbus.Endianness(x.Config.EncodingConfig.Endianness),
		modbus.WordOrder(x.Config.EncodingConfig.WordOrder),
	)
}

// initClient 构建并打开 modbus 连接。
func (x *modbusConn) initClient() (*modbus.ModbusClient, error) {
	config := &modbus.ClientConfiguration{
		URL:      x.Config.Server,
		Speed:    x.Config.RtuConfig.Speed,
		DataBits: x.Config.RtuConfig.DataBits,
		StopBits: x.Config.RtuConfig.StopBits,
		Timeout:  time.Duration(x.Config.TcpConfig.Timeout) * time.Second,
		Parity:   x.Config.RtuConfig.Parity,
	}
	if strings.HasPrefix(x.Config.Server, "tcp+tls://") {
		clientKeyPair, err := tls.LoadX509KeyPair(x.Config.TcpConfig.CertFile, x.Config.TcpConfig.CertKeyFile)
		if err != nil {
			return nil, err
		}
		config.TLSClientCert = &clientKeyPair
		config.TLSRootCAs, err = modbus.LoadCertPool(x.Config.TcpConfig.CAFile)
		if err != nil {
			return nil, err
		}
	}
	conn, err := modbus.NewClient(config)
	if err != nil {
		return nil, err
	}
	conn.SetEncoding(modbus.Endianness(x.Config.EncodingConfig.Endianness), modbus.WordOrder(x.Config.EncodingConfig.WordOrder))
	conn.SetUnitId(x.Config.UnitId)
	if err = conn.Open(); err != nil {
		return nil, err
	}
	return conn, nil
}

// reconnect 安全重建连接。ref:// 借用方委托源节点或返回错误；本地 owner 重建后 Refresh 更新 holder。
func (x *modbusConn) reconnect(old *modbus.ModbusClient) (*modbus.ModbusClient, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(modbusPointsReconnecter); ok { // 跨类型：Read↔Write 均可委派
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("modbus ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		modbusOpLocks.Delete(old) // 清理旧连接的操作锁条目
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := x.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

// ------------------------------------------------------------------------------------------------
// ReadPointsNode modbus 点位读取节点
// ------------------------------------------------------------------------------------------------

// ReadPointsNode 批量读取 Modicon 点位，结果(统一契约 Data 列表)写回 msg.Data，经 Success 链转出。
//
// 点位来源（双入口，msg.Data 优先）：配置 points(addr=Modicon)；或 msg.Data 带点位。
// 输出(msg.Data)：[{"name","value","timestamp","error"}]
type ReadPointsNode struct {
	modbusConn
}

func (x *ReadPointsNode) New() types.Node {
	return &ReadPointsNode{
		modbusConn: modbusConn{
			Config: PointsConfiguration{
				Server:         DefaultServer,
				UnitId:         DefaultUnitId,
				TcpConfig:      TcpConfig{Timeout: 5},
				EncodingConfig: EncodingConfig{Endianness: uint(DefaultEndianness), WordOrder: uint(DefaultWordOrder)},
				RtuConfig:      RtuConfig{Speed: DefaultSpeed, DataBits: DefaultDataBits, Parity: DefaultParity, StopBits: 2},
				Points: []iot_points.Point{
					{Name: "temperature", Addr: "40001", Type: "FLOAT32"},
				},
			},
		},
	}
}

func (x *ReadPointsNode) Type() string {
	return "x/modbusRead"
}

func (x *ReadPointsNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.setUnitId(nil, x.Config.UnitId)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*modbus.ModbusClient, error) {
		return x.initClient()
	}, func(client *modbus.ModbusClient) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	// 启用同链连接池：本地连接按节点ID注册到链目录
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *ReadPointsNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no modbus points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rendered := make([]iot_points.Point, len(pts))
	for i := range pts {
		rendered[i] = iot_points.RenderPoint(pts[i], env)
	}
	data, err := newDriver(x.newRetryableClient(client)).ReadPoints(rendered)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	b, mErr := json.Marshal(data)
	if mErr != nil {
		ctx.TellFailure(msg, mErr)
		return
	}
	msg.SetDataType(types.JSON)
	msg.SetData(string(b))
	ctx.TellSuccess(msg)
}

func (x *ReadPointsNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // 仅 owner 清理自己的操作锁
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			modbusOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

func (x *ReadPointsNode) Desc() string {
	return "Modbus client for batch reading points (Modicon addr). Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WritePointsNode modbus 点位写入节点
// ------------------------------------------------------------------------------------------------

// WriteNode 把点位值写入 Modbus（addr=Modicon），成功走 Success 链，否则 Failure 链。
//
// 点位来源（双入口，msg.Data 优先）：配置 points；或 msg.Data 带点位（value 为写入值）。
type WritePointsNode struct {
	modbusConn
}

func (x *WritePointsNode) New() types.Node {
	return &WritePointsNode{
		modbusConn: modbusConn{
			Config: PointsConfiguration{
				Server:         DefaultServer,
				UnitId:         DefaultUnitId,
				TcpConfig:      TcpConfig{Timeout: 5},
				EncodingConfig: EncodingConfig{Endianness: uint(DefaultEndianness), WordOrder: uint(DefaultWordOrder)},
				RtuConfig:      RtuConfig{Speed: DefaultSpeed, DataBits: DefaultDataBits, Parity: DefaultParity, StopBits: 2},
				Points: []iot_points.Point{
					{Name: "setpoint", Addr: "40010", Type: "FLOAT32", Value: "${msg.value}"},
				},
			},
		},
	}
}

func (x *WritePointsNode) Type() string {
	return "x/modbusWrite"
}

func (x *WritePointsNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.setUnitId(nil, x.Config.UnitId)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*modbus.ModbusClient, error) {
		return x.initClient()
	}, func(client *modbus.ModbusClient) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *WritePointsNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no modbus points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rendered := make([]iot_points.Point, len(pts))
	for i := range pts {
		rendered[i] = iot_points.RenderPoint(pts[i], env)
	}
	if err := newDriver(x.newRetryableClient(client)).WritePoints(rendered); err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	ctx.TellSuccess(msg)
}

func (x *WritePointsNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			modbusOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

func (x *WritePointsNode) Desc() string {
	return "Modbus client for writing points (Modicon addr). Routes to Success/Failure"
}
