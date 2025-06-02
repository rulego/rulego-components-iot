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
	"errors"
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
	Server string `json:"server"`
	// Modbus 方法名称
	Cmd string `json:"cmd"`
	// UnitId 从机编号
	UnitId uint8 `json:"unitId"`
	// address 寄存器地址 允许使用 ${} 占位符变量，示例：50或者0x32
	Address string `json:"address"`
	// quantity 寄存器数量 允许使用 ${} 占位符变量
	Quantity string `json:"quantity"`
	// value 寄存器值 允许使用 ${} 占位符变量。。读则不需要提供，如果写入多个与逗号隔开，例如：0x1,0x1 true 51,52
	Value string `json:"value"`
	// RegType 寄存器类型：  允许使用 ${} 占位符变量，0:保持寄存器(功能码0x3)，1:输入寄存器(功能码:0x4)
	RegType        string         `json:"regType"`
	TcpConfig      TcpConfig      `json:"tcpConfig"`
	RtuConfig      RtuConfig      `json:"rtuConfig"`
	EncodingConfig EncodingConfig `json:"encodingConfig"`
}

type EncodingConfig struct {
	// Endianness register endianness 1:大端序 2:小端序
	Endianness uint `json:"endianness"`
	// WordOrder word ordering for 32-bit registers 1:高字在前 2:低字在前
	WordOrder uint `json:"wordorder"`
}

type TcpConfig struct {
	// Timeout sets the request timeout value,单位秒
	Timeout int64 `json:"timeout"`
	// CertPath
	CertPath string `json:"certPath"`
	// KeyPath
	KeyPath string `json:"keyPath"`
	// CaPath
	CaPath string `json:"caPath"`
}

type RtuConfig struct {
	// Speed sets the serial link speed (in bps, rtu only)
	Speed uint `json:"speed"`
	// DataBits sets the number of bits per serial character (rtu only)
	DataBits uint `json:"dataBits"`
	// Parity sets the serial link parity mode (rtu only)
	Parity uint `json:"parity"`
	// StopBits sets the number of serial stop bits (rtu only)
	StopBits uint `json:"stopBits"`
}

// ModbusNode 客户端节点，
// 成功：转向Success链，发送消息执行结果存放在msg.Data
// 失败：转向Failure链
type ModbusNode struct {
	base.SharedNode[*modbus.ModbusClient]
	//节点配置
	Config           ModbusConfiguration
	conn             *modbus.ModbusClient
	addressTemplate  str.Template
	quantityTemplate str.Template
	valueTemplate    str.Template
	regTypeTemplate  str.Template
}

type Params struct {
	Cmd      string         `json:"cmd" `
	Address  uint16         `json:"address" `
	Quantity uint16         `json:"quantity" `
	Value    string         `json:"value" `
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
			Server:   DefaultServer,
			Cmd:      "ReadCoils",
			UnitId:   DefaultUnitId,
			Address:  "50",
			Quantity: "1",
			Value:    "1",
			RegType:  "0",
			TcpConfig: TcpConfig{
				Timeout: 5,
			},
			EncodingConfig: EncodingConfig{
				Endianness: uint(DefaultEndianness),
				WordOrder:  uint(DefaultWordOrder),
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
		err = x.SharedNode.Init(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*modbus.ModbusClient, error) {
			return x.initClient()
		})
	}
	//初始化模板
	x.addressTemplate = str.NewTemplate(x.Config.Address)
	x.quantityTemplate = str.NewTemplate(x.Config.Quantity)
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
		for i := range data {
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
		err = x.conn.WriteBytes(params.Address, []byte(params.Value))
	case "WriteRawBytes":
		err = x.conn.WriteRawBytes(params.Address, []byte(params.Value))
	default:
		err = fmt.Errorf("unknown command：%s", x.Config.Cmd)
	}
	if err != nil {
		ctx.TellFailure(msg, err)
	} else {
		if len(data) > 0 {
			bytes, err := json.Marshal(data)
			if err != nil {
				ctx.TellFailure(msg, err)
				return
			}
			msg.SetData(str.ToString(bytes))
		}
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
		regType   modbus.RegType = modbus.HOLDING_REGISTER
		params                   = Params{}
	)
	evn := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	// 获取address
	if strings.TrimSpace(x.addressTemplate.Execute(evn)) != "" {
		tmp, err = strconv.ParseUint(x.addressTemplate.Execute(evn), 0, 64)
		if err != nil {
			return nil, err
		}
		address = uint16(tmp)
	}
	// 获取quantity
	if strings.TrimSpace(x.quantityTemplate.Execute(evn)) != "" {
		tmp, err = strconv.ParseUint(x.quantityTemplate.Execute(evn), 0, 64)
		if err != nil {
			return nil, err
		}
		quanitity = uint16(tmp)
	}

	// 获取regType
	if strings.TrimSpace(x.regTypeTemplate.Execute(evn)) != "" {
		tmp, err = strconv.ParseUint(x.regTypeTemplate.Execute(evn), 0, 64)
		if err != nil {
			return nil, err
		}
		regType = modbus.RegType(tmp)
	}
	val = x.valueTemplate.Execute(evn)
	//value = []byte(val)
	// 更新参数
	params.Cmd = x.Config.Cmd
	params.Address = address
	params.Quantity = quanitity
	params.Value = val
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
			Speed:    x.Config.RtuConfig.Speed,
			DataBits: x.Config.RtuConfig.DataBits,
			StopBits: x.Config.RtuConfig.StopBits,
			Timeout:  time.Duration(x.Config.TcpConfig.Timeout) * time.Second,
			Parity:   x.Config.RtuConfig.Parity,
		}
		// handle TLS options
		if strings.HasPrefix(x.Config.Server, "tcp+tls://") {
			clientKeyPair, err := tls.LoadX509KeyPair(x.Config.TcpConfig.CertPath, x.Config.TcpConfig.KeyPath)
			if err != nil {
				x.Printf("failed to load client tls key pair: %v\n", err)
				return nil, err
			}
			config.TLSClientCert = &clientKeyPair

			config.TLSRootCAs, err = modbus.LoadCertPool(x.Config.TcpConfig.CaPath)
			if err != nil {
				x.Printf("failed to load tls CA/server certificate: %v\n", err)
				return nil, err
			}
		}

		x.conn, err = modbus.NewClient(config)
		x.conn.SetEncoding(modbus.Endianness(x.Config.EncodingConfig.Endianness), modbus.WordOrder(x.Config.EncodingConfig.WordOrder))
		x.conn.SetUnitId(x.Config.UnitId)
		if err != nil {
			return nil, err
		}
		err = x.conn.Open()
		return x.conn, err
	}
}

// byteToBool 将string转换为bool，支持,01,true,false
func byteToBool(data string) (bool, error) {
	switch strings.ToLower(data) {
	case "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, errors.New("invalid boolean value")
	}
}

// byteToBools 将string转换为bool列表，支持"[0,1]","[true,false]","true,false"
func byteToBools(data string) ([]bool, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	bools := make([]bool, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if b, err := byteToBool(part); err == nil {
			bools = append(bools, b)
		} else {
			return nil, err
		}
	}
	return bools, nil
}

// byteToUint64 将string转换为uint64，支持"0x32","50"
func byteToUint64(data string) (uint64, error) {
	return strconv.ParseUint(data, 0, 64)
}

// byteToUint64s 将string转换为uint64列表，支持"[0x32,50]","[32,50]","32,50"
func byteToUint64s(data string) ([]uint64, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	u64s := make([]uint64, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if u64, err := byteToUint64(part); err == nil {
			u64s = append(u64s, u64)
		} else {
			return nil, err
		}
	}
	return u64s, nil
}

// byteToUint32 将string转换为uint32，支持"0x32","50"
func byteToUint32(data string) (uint32, error) {
	if temp, err := strconv.ParseUint(data, 0, 32); err == nil {
		return uint32(temp), nil
	} else {
		return 0, err
	}
}

// byteToUint32s 将string转换为uint32列表，支持"[0x32,50]","[32,50]","32,50"
func byteToUint32s(data string) ([]uint32, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	u32s := make([]uint32, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if u32, err := byteToUint32(part); err == nil {
			u32s = append(u32s, u32)
		} else {
			return nil, err
		}
	}
	return u32s, nil
}

// byteToUint16 将string转换为uint16，支持"0x32","50"
func byteToUint16(data string) (uint16, error) {
	if temp, err := strconv.ParseUint(data, 0, 16); err == nil {
		return uint16(temp), nil
	} else {
		return 0, err
	}
}

// byteToUint16s 将string转换为uint16列表，支持"[0x32,50]","[32,50]","32,50"
func byteToUint16s(data string) ([]uint16, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	u16s := make([]uint16, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if u16, err := byteToUint16(part); err == nil {
			u16s = append(u16s, u16)
		} else {
			return nil, err
		}
	}
	return u16s, nil
}

// byteToFloat32 将string转换为float32
func byteToFloat32(data string) (float32, error) {
	f64, err := strconv.ParseFloat(data, 32)
	return float32(f64), err
}

// byteToFloat32s 将string转换为float32列表，支持"[1.2,3.4]","1.2,3.4"
func byteToFloat32s(data string) ([]float32, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	f32s := make([]float32, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if f32, err := byteToFloat32(part); err == nil {
			f32s = append(f32s, f32)
		} else {
			return nil, err
		}
	}
	return f32s, nil
}

// byteToFloat64 将string转换为float64
func byteToFloat64(data string) (float64, error) {
	return strconv.ParseFloat(data, 64)
}

// byteToFloat64s 将string转换为float64列表，支持"[1.2,3.4]","1.2,3.4"
func byteToFloat64s(data string) ([]float64, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	f64s := make([]float64, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if f64, err := byteToFloat64(part); err == nil {
			f64s = append(f64s, f64)
		} else {
			return nil, err
		}
	}
	return f64s, nil
}
