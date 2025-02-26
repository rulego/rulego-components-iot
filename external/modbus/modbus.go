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
	"reflect"
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
	// UnitId unit/slave id to use
	UnitId uint8
	// address 寄存器地址:允许使用 ${} 占位符变量
	Address string
	// quantity 寄存器数量:允许使用 ${} 占位符变量
	Quantity string
	// value 寄存器值:  允许使用 ${} 占位符变量
	Value string
	// RegType 寄存器类型：  允许使用 ${} 占位符变量
	RegType string
	TcpConfig
	RtuConfig
	EncodingConfig
}

type EncodingConfig struct {
	// Endianness register endianness <little|big>
	Endianness modbus.Endianness
	// WordOrder word ordering for 32-bit registers <highfirst|hf|lowfirst|lf>
	WordOrder modbus.WordOrder
}

type TcpConfig struct {
	// Timeout sets the request timeout value,单位秒
	Timeout int64
	// CertPath
	CertPath string
	// KeyPath
	KeyPath string
	// CaPath
	CaPath string
}

type RtuConfig struct {
	// Speed sets the serial link speed (in bps, rtu only)
	Speed uint
	// DataBits sets the number of bits per serial character (rtu only)
	DataBits uint
	// Parity sets the serial link parity mode (rtu only)
	Parity uint
	// StopBits sets the number of serial stop bits (rtu only)
	StopBits uint
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

type ModbusValue struct {
	UnitId  uint8  `json:"unitId"`
	Type    string `json:"type" `
	Address uint16 `json:"address"`
	Value   any    `json:"value" `
}

// Type 返回组件类型
func (x *ModbusNode) Type() string {
	return "x/modbus"
}

// New 默认参数
func (x *ModbusNode) New() types.Node {
	return &ModbusNode{
		Config: ModbusConfiguration{
			Server: DefaultServer,
			Cmd:    "ReadCoils",
			UnitId: DefaultUnitId,
			TcpConfig: TcpConfig{
				Timeout: 5,
			},
			EncodingConfig: EncodingConfig{
				Endianness: DefaultEndianness,
				WordOrder:  DefaultWordOrder,
			},
			RtuConfig: RtuConfig{
				Speed:    DefaultSpeed,
				DataBits: DefaultDataBits,
				Parity:   DefaultParity,
				StopBits: 2,
			},
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

func readModbusValues[T bool | uint16 | uint32 | uint64 | float32 | float64 | byte](data []T, initAddr uint16, step uint16, unitId uint8) []ModbusValue {
	addVals := make([]ModbusValue, 0)
	// Get the reflect.Value of the slice
	sliceValue := reflect.ValueOf(data)
	// Get the type of the slice
	sliceType := sliceValue.Type()
	// Get the element type of the slice
	elemType := sliceType.Elem()
	if elemType == reflect.TypeOf(byte(0)) {
		step = 1
		for i, _ := range data {
			if i%2 == 0 {
				addVals = append(addVals, ModbusValue{
					UnitId:  unitId,
					Address: initAddr + uint16(i)*step,
					Value:   data[i : i+1],
					Type:    elemType.Name(),
				})
			}
		}

	} else {
		for i, v := range data {
			addVals = append(addVals, ModbusValue{
				UnitId:  unitId,
				Address: initAddr + uint16(i)*step,
				Value:   v,
				Type:    elemType.Name(),
			})
		}
	}
	return addVals
}

// OnMsg 处理消息
func (x *ModbusNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	// x.Locker.Lock()
	// defer x.Locker.Unlock()
	var (
		err      error
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
		bts      []byte
		data     []ModbusValue = make([]ModbusValue, 0)
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
	switch x.Config.Cmd {
	case "ReadCoils":
		boolVals, err = x.conn.ReadCoils(params.Address, params.Quantity)
		if err == nil {
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadCoil":
		boolVal, err = x.conn.ReadCoil(params.Address)
		if err == nil {
			boolVals = append(boolVals, boolVal)
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadDiscreteInputs":
		boolVals, err = x.conn.ReadDiscreteInputs(params.Address, params.Quantity)
		if err == nil {
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadDiscreteInput":
		boolVal, err = x.conn.ReadDiscreteInput(params.Address)
		if err == nil {
			boolVals = append(boolVals, boolVal)
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadRegisters":
		ui16s, err = x.conn.ReadRegisters(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(ui16s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadRegister":
		ui16, err = x.conn.ReadRegister(params.Address, params.RegType)
		if err == nil {
			ui16s = append(ui16s, ui16)
			data = readModbusValues(ui16s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadUint32s":
		ui32s, err = x.conn.ReadUint32s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(ui32s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadUint32":
		ui32, err = x.conn.ReadUint32(params.Address, params.RegType)
		if err == nil {
			ui32s = append(ui32s, ui32)
			data = readModbusValues(ui32s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadFloat32s":
		f32s, err = x.conn.ReadFloat32s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(f32s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadFloat32":
		f32, err = x.conn.ReadFloat32(params.Address, params.RegType)
		if err == nil {
			f32s = append(f32s, f32)
			data = readModbusValues(f32s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadUint64s":
		ui64s, err = x.conn.ReadUint64s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(ui64s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadUint64":
		ui64, err = x.conn.ReadUint64(params.Address, params.RegType)
		if err == nil {
			ui64s = append(ui64s, ui64)
			data = readModbusValues(ui64s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadFloat64s":
		f64s, err = x.conn.ReadFloat64s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(f64s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadFloat64":
		f64, err = x.conn.ReadFloat64(params.Address, params.RegType)
		if err == nil {
			f64s = append(f64s, f64)
			data = readModbusValues(f64s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadBytes":
		bts, err = x.conn.ReadBytes(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(bts, params.Address, 1, x.Config.UnitId)
		}
	case "ReadRawBytes":
		bts, err = x.conn.ReadRawBytes(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(bts, params.Address, 1, x.Config.UnitId)
		}
	case "WriteCoil":
		boolVal, err = byteToBool(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteCoil(params.Address, boolVal)
	case "WriteCoils":
		boolVals, err = byteToBools(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteCoils(params.Address, boolVals)
	case "WriteRegister":
		ui16, err = byteToUint16(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteRegister(params.Address, ui16)
	case "WriteRegisters":
		ui16s, err = byteToUint16s(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteRegisters(params.Address, ui16s)
	case "WriteUint32":
		ui32, err = byteToUint32(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteUint32(params.Address, ui32)
	case "WriteUint32s":
		ui32s, err = byteToUint32s(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteUint32s(params.Address, ui32s)
	case "WriteFloat32":
		f32, err = byteToFloat32(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteFloat32(params.Address, f32)
	case "WriteFloat32s":
		f32s, err = byteToFloat32s(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteFloat32s(params.Address, f32s)
	case "WriteUint64":
		ui64, err = byteToUint64(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteUint64(params.Address, ui64)
	case "WriteUint64s":
		ui64s, err = byteToUint64s(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteUint64s(params.Address, ui64s)
	case "WriteFloat64":
		f64, err = byteToFloat64(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
		err = x.conn.WriteFloat64(params.Address, f64)
	case "WriteFloat64s":
		f64s, err = byteToFloat64s(params.Value)
		if err != nil {
			x.Printf("convert value error:%s", err)
		}
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
		bytes, err := json.Marshal(data)
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
