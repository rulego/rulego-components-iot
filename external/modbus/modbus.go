/*
 * Copyright 2025 The RuleGo Authors.
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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
	"github.com/rulego/rulego/utils/str"
	"github.com/simonvetter/modbus"
)

const (
	DefaultServer                       = "tcp://127.0.0.1:502"
	DefaultSpeed      uint              = 19200
	DefaultDataBits   uint              = 8
	DefaultParity     uint              = modbus.PARITY_NONE
	DefaultStopBits   uint              = 2
	DefaultTimeout    time.Duration     = time.Second * 5
	DefaultEndianness modbus.Endianness = modbus.BIG_ENDIAN
	DefaultWordOrder  modbus.WordOrder  = modbus.HIGH_WORD_FIRST
	DefaultUnitId     uint8             = 1
)

// 注册节点
func init() {
	_ = rulego.Registry.Register(&ModbusNode{})
}

// ModbusConfiguration 节点配置
type ModbusConfiguration struct {
	// 服务器地址
	Server string
	// Modbus 方法名称
	Cmd string
	// address 寄存器地址:允许使用 ${} 占位符变量
	Address string
	// quantity 寄存器数量:允许使用 ${} 占位符变量
	Quantity string
	// value 寄存器值:  允许使用 ${} 占位符变量
	Value string
	// RegType 寄存器类型：  允许使用 ${} 占位符变量
	RegType string
	// UnitId unit/slave id to use
	UnitId uint8
	// Timeout sets the request timeout value,单位秒
	Timeout int64
	// Endianness register endianness <little|big>
	Endianness modbus.Endianness
	// WordOrder word ordering for 32-bit registers <highfirst|hf|lowfirst|lf>
	WordOrder modbus.WordOrder

	// Speed sets the serial link speed (in bps, rtu only)
	Speed uint
	// DataBits sets the number of bits per serial character (rtu only)
	DataBits uint
	// Parity sets the serial link parity mode (rtu only)
	Parity uint
	// StopBits sets the number of serial stop bits (rtu only)
	StopBits uint

	// CertPath
	CertPath string
	// KeyPath
	KeyPath string
	// CaPath
	CaPath string
}

// ModbusNode 客户端节点，
// 成功：转向Success链，发送消息执行结果存放在msg.Data
// 失败：转向Failure链
type ModbusNode struct {
	base.SharedNode[*modbus.ModbusClient]
	//节点配置
	Config            ModbusConfiguration
	conn              *modbus.ModbusClient
	addressTemplate   str.Template
	quanitityTemplate str.Template
	valueTemplate     str.Template
	regTypeTemplate   str.Template
}

type Params struct {
	Cmd      string         `json:"cmd" `
	Address  uint16         `json:"address" `
	Quantity uint16         `json:"quantity" `
	Value    []byte         `json:"-" `
	Val      string         `json:"value" `
	RegType  modbus.RegType `json:"regType" `
}

type ModbusData struct {
	Params *Params `json:"params" `
	Data   any     `json:"data" `
}

// Type 返回组件类型
func (x *ModbusNode) Type() string {
	return "x/modbus"
}

// New 默认参数
func (x *ModbusNode) New() types.Node {
	return &ModbusNode{
		Config: ModbusConfiguration{
			Server:     DefaultServer,
			Cmd:        "ReadCoils",
			Timeout:    5,
			UnitId:     DefaultUnitId,
			Endianness: DefaultEndianness,
			WordOrder:  DefaultWordOrder,
			Speed:      DefaultSpeed,
			DataBits:   DefaultDataBits,
			Parity:     DefaultParity,
			StopBits:   2,
		},
	}
}

// Init 初始化组件
func (x *ModbusNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	if err == nil {
		//初始化客户端
		err = x.SharedNode.Init(ruleConfig, x.Type(), x.Config.Server, true, func() (*modbus.ModbusClient, error) {
			return x.initClient()
		})
	}
	//初始化模板
	x.addressTemplate = str.NewTemplate(x.Config.Address)
	x.quanitityTemplate = str.NewTemplate(x.Config.Quantity)
	x.valueTemplate = str.NewTemplate(x.Config.Value)
	x.regTypeTemplate = str.NewTemplate(x.Config.RegType)
	return err
}

// OnMsg 处理消息
func (x *ModbusNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	// x.Locker.Lock()
	// defer x.Locker.Unlock()
	var (
		err      error
		data     any
		params   *Params
		boolVals []bool
		boolVal  bool
		ui16     uint16
		ui32     uint32
		ui64     uint64
		f32      float32
		f64      float64
		ui16s    []uint16
		ui32s    []uint32
		ui64s    []uint64
		f32s     []float32
		f64s     []float64
		result   ModbusData = ModbusData{}
	)
	x.conn, err = x.SharedNode.Get()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	params, err = x.getParams(ctx, msg)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	result.Params = params

	switch x.Config.Cmd {
	case "ReadCoils":
		data, err = x.conn.ReadCoils(params.Address, params.Quantity)
	case "ReadCoil":
		data, err = x.conn.ReadCoil(params.Address)
	case "ReadDiscreteInputs":
		data, err = x.conn.ReadDiscreteInputs(params.Address, params.Quantity)
	case "ReadDiscreteInput":
		data, err = x.conn.ReadDiscreteInput(params.Address)
	case "ReadRegisters":
		data, err = x.conn.ReadRegisters(params.Address, params.Quantity, params.RegType)
	case "ReadRegister":
		data, err = x.conn.ReadRegister(params.Address, params.RegType)
	case "ReadUint32s":
		data, err = x.conn.ReadUint32s(params.Address, params.Quantity, params.RegType)
	case "ReadUint32":
		data, err = x.conn.ReadUint32(params.Address, params.RegType)
	case "ReadFloat32s":
		data, err = x.conn.ReadFloat32s(params.Address, params.Quantity, params.RegType)
	case "ReadFloat32":
		data, err = x.conn.ReadFloat32(params.Address, params.RegType)
	case "ReadUint64s":
		data, err = x.conn.ReadUint64s(params.Address, params.Quantity, params.RegType)
	case "ReadUint64":
		data, err = x.conn.ReadUint64(params.Address, params.RegType)
	case "ReadFloat64s":
		data, err = x.conn.ReadFloat64s(params.Address, params.Quantity, params.RegType)
	case "ReadFloat64":
		data, err = x.conn.ReadFloat64(params.Address, params.RegType)
	case "ReadBytes":
		data, err = x.conn.ReadBytes(params.Address, params.Quantity, params.RegType)
	case "ReadRawBytes":
		data, err = x.conn.ReadRawBytes(params.Address, params.Quantity, params.RegType)
	case "WriteCoil":
		boolVal, err = byteToBool(params.Value)
		err = x.conn.WriteCoil(params.Address, boolVal)
	case "WriteCoils":
		boolVals, err = byteToBools(params.Value)
		err = x.conn.WriteCoils(params.Address, boolVals)
	case "WriteRegister":
		ui16, _ = byteToUint16(params.Value)
		err = x.conn.WriteRegister(params.Address, ui16)
	case "WriteRegisters":
		ui16s, _ = byteToUint16s(params.Value)
		err = x.conn.WriteRegisters(params.Address, ui16s)
	case "WriteUint32":
		ui32, _ = byteToUint32(params.Value)
		err = x.conn.WriteUint32(params.Address, ui32)
	case "WriteUint32s":
		ui32s, _ = byteToUint32s(params.Value)
		err = x.conn.WriteUint32s(params.Address, ui32s)
	case "WriteFloat32":
		f32, _ = byteToFloat32(params.Value)
		err = x.conn.WriteFloat32(params.Address, f32)
	case "WriteFloat32s":
		f32s, _ = byteToFloat32s(params.Value)
		err = x.conn.WriteFloat32s(params.Address, f32s)
	case "WriteUint64":
		ui64, _ = byteToUint64(params.Value)
		err = x.conn.WriteUint64(params.Address, ui64)
	case "WriteUint64s":
		ui64s, _ = byteToUint64s(params.Value)
		err = x.conn.WriteUint64s(params.Address, ui64s)
	case "WriteFloat64":
		f64, _ = byteToFloat64(params.Value)
		err = x.conn.WriteFloat64(params.Address, f64)
	case "WriteFloat64s":
		f64s, _ = byteToFloat64s(params.Value)
		err = x.conn.WriteFloat64s(params.Address, f64s)
	case "WriteBytes":
		err = x.conn.WriteBytes(params.Address, params.Value)
	case "WriteRawBytes":
		err = x.conn.WriteRawBytes(params.Address, params.Value)
	default:
		err = fmt.Errorf("unknown command：%s", x.Config.Cmd)
	}
	if err != nil {
		ctx.TellFailure(msg, err)
	} else {
		result.Data = data
		bytes, err := json.Marshal(result)
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
		msg.Data = str.ToString(bytes)
		ctx.TellSuccess(msg)
	}
}

// getParams 获取参数
func (x *ModbusNode) getParams(ctx types.RuleContext, msg types.RuleMsg) (*Params, error) {
	var (
		err       error
		tmp       uint64
		address   uint16
		quanitity uint16
		val       string
		value     []byte
		regType   modbus.RegType = modbus.HOLDING_REGISTER
		params                   = Params{}
	)
	evn := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	// 获取address
	if !x.addressTemplate.IsNotVar() {
		tmp, err = strconv.ParseUint(x.addressTemplate.Execute(evn), 10, 16)
		address = uint16(tmp)
	} else if len(x.Config.Address) > 0 {
		tmp, err = strconv.ParseUint(x.Config.Address, 10, 16)
		address = uint16(tmp)
	}
	// 获取quantity
	if !x.quanitityTemplate.IsNotVar() {
		tmp, err = strconv.ParseUint(x.addressTemplate.Execute(evn), 10, 16)
		quanitity = uint16(tmp)
	} else if len(x.Config.Quantity) > 0 {
		tmp, err = strconv.ParseUint(x.Config.Quantity, 10, 16)
		quanitity = uint16(tmp)
	}
	// 获取regType
	if !x.regTypeTemplate.IsNotVar() {
		tmp, err = strconv.ParseUint(x.regTypeTemplate.Execute(evn), 10, 16)
		regType = modbus.RegType(tmp)
	} else if len(x.Config.RegType) > 0 {
		tmp, err = strconv.ParseUint(x.Config.RegType, 10, 16)
		regType = modbus.RegType(tmp)
	}
	// 获取value
	if !x.valueTemplate.IsNotVar() {
		val = x.valueTemplate.Execute(evn)
		value = []byte(val)
	} else if len(x.Config.Value) > 0 {
		val = x.Config.Value
		value = []byte(val)
	}
	if err != nil {
		return nil, err
	}
	// 更新参数
	params.Cmd = x.Config.Cmd
	params.Address = address
	params.Quantity = quanitity
	params.Value = value
	params.Val = val
	params.RegType = regType
	return &params, nil
}

// Destroy 销毁组件
func (x *ModbusNode) Destroy() {
	if x.conn != nil {
		_ = x.conn.Close()
		x.conn = nil
	}
}

// Printf 打印日志
func (x *ModbusNode) Printf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Printf(format, v...)
	}
}

// 初始化连接
func (x *ModbusNode) initClient() (*modbus.ModbusClient, error) {
	if x.conn != nil {
		return x.conn, nil
	} else {
		x.Locker.Lock()
		defer x.Locker.Unlock()
		if x.conn != nil {
			return x.conn, nil
		}
		var err error
		config := &modbus.ClientConfiguration{
			URL:      x.Config.Server,
			Speed:    x.Config.Speed,
			DataBits: x.Config.DataBits,
			StopBits: x.Config.StopBits,
			Timeout:  time.Duration(x.Config.Timeout) * time.Second,
			Parity:   x.Config.Parity,
		}
		// handle TLS options
		if strings.HasPrefix(x.Config.Server, "tcp+tls://") {
			clientKeyPair, err := tls.LoadX509KeyPair(x.Config.CertPath, x.Config.KeyPath)
			if err != nil {
				x.Printf("failed to load client tls key pair: %v\n", err)
				return nil, err
			}
			config.TLSClientCert = &clientKeyPair

			config.TLSRootCAs, err = modbus.LoadCertPool(x.Config.CaPath)
			if err != nil {
				x.Printf("failed to load tls CA/server certificate: %v\n", err)
				return nil, err
			}
		}

		x.conn, err = modbus.NewClient(config)
		x.conn.SetEncoding(x.Config.Endianness, x.Config.WordOrder)
		x.conn.SetUnitId(x.Config.UnitId)
		if err != nil {
			return nil, err
		}
		err = x.conn.Open()
		return x.conn, err
	}
}

func byteToBool(data []byte) (bool, error) {
	var value bool
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToBools(data []byte) ([]bool, error) {
	var value []bool
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToUint64(data []byte) (uint64, error) {
	var value uint64
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToUint64s(data []byte) ([]uint64, error) {
	var value []uint64
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToUint32(data []byte) (uint32, error) {
	var value uint32
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToUint32s(data []byte) ([]uint32, error) {
	var value []uint32
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToUint16(data []byte) (uint16, error) {
	var value uint16
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToUint16s(data []byte) ([]uint16, error) {
	var value []uint16
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToFloat32(data []byte) (float32, error) {
	var value float32
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToFloat32s(data []byte) ([]float32, error) {
	var value []float32
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToFloat64(data []byte) (float64, error) {
	var value float64
	err := json.Unmarshal(data, &value)
	return value, err
}

func byteToFloat64s(data []byte) ([]float64, error) {
	var value []float64
	err := json.Unmarshal(data, &value)
	return value, err
}
