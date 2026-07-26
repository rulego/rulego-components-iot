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
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/simonvetter/modbus"
)

// Modicon 地址类型（首数字区分）。
const (
	modiconCoil = "coil"             // 0xxxx 线圈（读写）
	modiconDI   = "discrete_input"   // 1xxxx 离散输入（只读）
	modiconIR   = "input_register"   // 3xxxx 输入寄存器（只读）
	modiconHR   = "holding_register" // 4xxxx 保持寄存器（读写）
)

// driver 适配 iot_points.Driver 到 RetryableModbusClient。无状态，持 client 引用。
type driver struct {
	client *RetryableModbusClient
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *RetryableModbusClient) *driver {
	return &driver{client: client}
}

// ReadPoints 按 Point.Addr(Modicon) + Type 读取。单点失败标记 Error；全部失败返回 error。
func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, 0, len(points))
	failCount := 0
	for _, p := range points {
		dd, err := d.readPoint(p)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			failCount++
		} else {
			out = append(out, dd)
		}
	}
	if len(points) > 0 && failCount == len(points) {
		return nil, fmt.Errorf("all %d modbus points failed", failCount)
	}
	return out, nil
}

// WritePoints 按 Point.Addr(Modicon) + Type 写入。任一失败立即返回 error。DI/IR 只读拒写。
func (d *driver) WritePoints(points []iot_points.Point) error {
	for _, p := range points {
		if err := d.writePoint(p); err != nil {
			return err
		}
	}
	return nil
}

// readPoint 读取单个点位。Type 决定调用的库方法与寄存器数量；Scale/Offset 做工程量转换。
func (d *driver) readPoint(p iot_points.Point) (iot_points.Data, error) {
	regType, addr, kind, err := parseModiconAddr(p.Addr)
	if err != nil {
		return iot_points.Data{}, err
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	var raw float64
	var val interface{}
	switch {
	case typ == iot_points.TypeBool || kind == modiconCoil || kind == modiconDI:
		b, err := d.readBool(addr, kind, regType)
		if err != nil {
			return iot_points.Data{}, err
		}
		val = b
		if b {
			raw = 1
		}
	case typ == iot_points.TypeUint16 || typ == iot_points.TypeInt16 || typ == "":
		v, err := d.client.ReadRegister(addr, regType)
		if err != nil {
			return iot_points.Data{}, err
		}
		if typ == iot_points.TypeInt16 {
			val = int16(v)
			raw = float64(int16(v))
		} else {
			val = v
			raw = float64(v)
		}
	case typ == iot_points.TypeUint32 || typ == iot_points.TypeInt32 || typ == iot_points.TypeFloat32:
		if p.Endian != "" {
			// 点位级字节序：读原始字序列后按 Endian 重排解码
			words, err := d.client.ReadRegisters(addr, 2, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			val, raw = decodeModbusWords(typ, applyEndian(words, p.Endian))
		} else {
			v, err := d.client.ReadUint32(addr, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			if typ == iot_points.TypeFloat32 {
				val = math.Float32frombits(v)
			} else if typ == iot_points.TypeInt32 {
				val = int32(v)
			} else {
				val = v
			}
			raw = float64(toFloat64(val))
		}
	case typ == iot_points.TypeUint64 || typ == iot_points.TypeInt64 || typ == iot_points.TypeFloat64:
		if p.Endian != "" {
			words, err := d.client.ReadRegisters(addr, 4, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			val, raw = decodeModbusWords(typ, applyEndian(words, p.Endian))
		} else {
			v, err := d.client.ReadUint64(addr, regType)
			if err != nil {
				return iot_points.Data{}, err
			}
			if typ == iot_points.TypeFloat64 {
				val = math.Float64frombits(v)
			} else if typ == iot_points.TypeInt64 {
				val = int64(v)
			} else {
				val = v
			}
			raw = float64(toFloat64(val))
		}
	default:
		return iot_points.Data{}, fmt.Errorf("unsupported modbus type %q", p.Type)
	}
	// 工程量转换（BOOL 不转换）
	if (p.Scale != 0 || p.Offset != 0) && typ != iot_points.TypeBool {
		val = iot_points.ApplyScale(raw, p)
	}
	return iot_points.Data{Name: p.Name, Value: val, Timestamp: time.Now().UnixNano()}, nil
}

// readBool 读位：线圈/离散输入按 kind 选方法；寄存器区(HR/IR) BOOL 取寄存器 bit0。
func (d *driver) readBool(addr uint16, kind string, regType modbus.RegType) (bool, error) {
	switch kind {
	case modiconDI:
		return d.client.ReadDiscreteInput(addr)
	case modiconCoil:
		return d.client.ReadCoil(addr)
	default:
		v, err := d.client.ReadRegister(addr, regType)
		if err != nil {
			return false, err
		}
		return v&1 != 0, nil
	}
}

// toFloat64 数值转 float64（用于 Scale 原始值）。
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case uint32:
		return float64(n)
	case int32:
		return float64(n)
	case float32:
		return float64(n)
	case uint64:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case uint16:
		return float64(n)
	case int16:
		return float64(n)
	}
	return 0
}

// applyEndian 按点位字节序重排字序列（设备原始序为 ABCD 大端高字在前）。
// CDAB=字交换、BADC=字内字节交换、DCBA=两者；四种变换均为对合，编解码同函数。
func applyEndian(words []uint16, endian string) []uint16 {
	e := strings.ToUpper(strings.TrimSpace(endian))
	if e == "" || e == "ABCD" {
		return words
	}
	out := make([]uint16, len(words))
	byteSwap := e == "BADC" || e == "DCBA"
	wordSwap := e == "CDAB" || e == "DCBA"
	for i, w := range words {
		j := i
		if wordSwap {
			j = len(words) - 1 - i
		}
		if byteSwap {
			w = w>>8 | w<<8
		}
		out[j] = w
	}
	return out
}

// decodeModbusWords 大端字序列(ABCD) -> 统一类型值与原始浮点。
func decodeModbusWords(typ string, w []uint16) (interface{}, float64) {
	u32 := uint32(w[0])<<16 | uint32(w[1])
	switch typ {
	case iot_points.TypeInt32:
		v := int32(u32)
		return v, float64(v)
	case iot_points.TypeUint32:
		return u32, float64(u32)
	case iot_points.TypeFloat32:
		v := math.Float32frombits(u32)
		return v, float64(v)
	}
	u64 := uint64(w[0])<<48 | uint64(w[1])<<32 | uint64(w[2])<<16 | uint64(w[3])
	switch typ {
	case iot_points.TypeInt64:
		v := int64(u64)
		return v, float64(v)
	case iot_points.TypeUint64:
		return u64, float64(u64)
	case iot_points.TypeFloat64:
		v := math.Float64frombits(u64)
		return v, v
	}
	return nil, 0
}

// encodeModbusWords 统一类型字符串值 -> 大端字序列(ABCD)。
func encodeModbusWords(typ, value string) ([]uint16, error) {
	switch typ {
	case iot_points.TypeInt32, iot_points.TypeUint32:
		var v uint64
		if typ == iot_points.TypeInt32 {
			s, err := strconv.ParseInt(value, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("parse int32 value %q: %w", value, err)
			}
			v = uint64(uint32(s))
		} else {
			u, err := strconv.ParseUint(value, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("parse uint32 value %q: %w", value, err)
			}
			v = u
		}
		return []uint16{uint16(v >> 16), uint16(v)}, nil
	case iot_points.TypeFloat32:
		f, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return nil, fmt.Errorf("parse float32 value %q: %w", value, err)
		}
		v := math.Float32bits(float32(f))
		return []uint16{uint16(v >> 16), uint16(v)}, nil
	case iot_points.TypeInt64, iot_points.TypeUint64:
		var v uint64
		if typ == iot_points.TypeInt64 {
			s, err := strconv.ParseInt(value, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("parse int64 value %q: %w", value, err)
			}
			v = uint64(s)
		} else {
			u, err := strconv.ParseUint(value, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("parse uint64 value %q: %w", value, err)
			}
			v = u
		}
		return []uint16{uint16(v >> 48), uint16(v >> 32), uint16(v >> 16), uint16(v)}, nil
	case iot_points.TypeFloat64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("parse float64 value %q: %w", value, err)
		}
		v := math.Float64bits(f)
		return []uint16{uint16(v >> 48), uint16(v >> 32), uint16(v >> 16), uint16(v)}, nil
	}
	return nil, fmt.Errorf("unsupported endian encode type %q", typ)
}

// writePoint 写入单个点位。寄存器类写仅限 HR；线圈类写仅限 Coil。
func (d *driver) writePoint(p iot_points.Point) error {
	_, addr, kind, err := parseModiconAddr(p.Addr)
	if err != nil {
		return err
	}
	if kind == modiconDI || kind == modiconIR {
		return fmt.Errorf("modbus %s addr %s is read-only", kind, p.Addr)
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	switch {
	case typ == iot_points.TypeBool || kind == modiconCoil:
		// BOOL 写仅支持线圈区
		if kind != modiconCoil {
			return fmt.Errorf("modbus BOOL write only supports Coil(00001) addr, got %s", p.Addr)
		}
		b, err := byteToBool(p.Value)
		if err != nil {
			return fmt.Errorf("parse bool value %q: %w", p.Value, err)
		}
		return d.client.WriteCoil(addr, b)
	case typ == iot_points.TypeUint16 || typ == iot_points.TypeInt16 || typ == "":
		if typ == iot_points.TypeInt16 {
			v, err := strconv.ParseInt(p.Value, 0, 16)
			if err != nil {
				return fmt.Errorf("parse int16 value %q: %w", p.Value, err)
			}
			return d.client.WriteRegister(addr, uint16(v))
		}
		v, err := strconv.ParseUint(p.Value, 0, 16)
		if err != nil {
			return fmt.Errorf("parse uint16 value %q: %w", p.Value, err)
		}
		return d.client.WriteRegister(addr, uint16(v))
	default:
		// 多寄存器类型：点位级 Endian 时编码为字序列按字节序写入
		if p.Endian != "" {
			words, err := encodeModbusWords(typ, p.Value)
			if err != nil {
				return err
			}
			return d.client.WriteRegisters(addr, applyEndian(words, p.Endian))
		}
		switch typ {
		case iot_points.TypeUint32, iot_points.TypeInt32:
			if typ == iot_points.TypeInt32 {
				v, err := strconv.ParseInt(p.Value, 0, 32)
				if err != nil {
					return fmt.Errorf("parse int32 value %q: %w", p.Value, err)
				}
				return d.client.WriteUint32(addr, uint32(v))
			}
			v, err := strconv.ParseUint(p.Value, 0, 32)
			if err != nil {
				return fmt.Errorf("parse uint32 value %q: %w", p.Value, err)
			}
			return d.client.WriteUint32(addr, uint32(v))
		case iot_points.TypeUint64, iot_points.TypeInt64:
			if typ == iot_points.TypeInt64 {
				v, err := strconv.ParseInt(p.Value, 0, 64)
				if err != nil {
					return fmt.Errorf("parse int64 value %q: %w", p.Value, err)
				}
				return d.client.WriteUint64(addr, uint64(v))
			}
			v, err := strconv.ParseUint(p.Value, 0, 64)
			if err != nil {
				return fmt.Errorf("parse uint64 value %q: %w", p.Value, err)
			}
			return d.client.WriteUint64(addr, v)
		case iot_points.TypeFloat32:
			f, err := strconv.ParseFloat(p.Value, 32)
			if err != nil {
				return fmt.Errorf("parse float32 value %q: %w", p.Value, err)
			}
			return d.client.WriteFloat32(addr, float32(f))
		case iot_points.TypeFloat64:
			f, err := strconv.ParseFloat(p.Value, 64)
			if err != nil {
				return fmt.Errorf("parse float64 value %q: %w", p.Value, err)
			}
			return d.client.WriteFloat64(addr, f)
		default:
			return fmt.Errorf("unsupported modbus type %q", p.Type)
		}
	}
}

// parseModiconAddr 解析 Modicon 传统地址（1-based）为协议地址（0-based）+ 类型。
//
//	00001-09999   -> Coil          (功能码 01/05/0F)
//	10001-19999   -> Discrete Input(功能码 02，只读)
//	30001-39999   -> Input Register(功能码 04，只读)
//	40001-49999   -> Holding Register(功能码 03/06/10)
//	400001-465535 -> Holding Register 扩展(6 位)
func parseModiconAddr(addr string) (regType modbus.RegType, protocolAddr uint16, kind string, err error) {
	n, perr := strconv.ParseUint(strings.TrimSpace(addr), 10, 32)
	if perr != nil {
		return 0, 0, "", fmt.Errorf("invalid modicon addr %q: %w", addr, perr)
	}
	switch {
	case n >= 1 && n <= 9999:
		kind = modiconCoil
		protocolAddr = uint16(n - 1)
	case n >= 10001 && n <= 19999:
		kind = modiconDI
		protocolAddr = uint16(n - 10001)
	case n >= 30001 && n <= 39999:
		kind = modiconIR
		regType = modbus.INPUT_REGISTER
		protocolAddr = uint16(n - 30001)
	case n >= 40001 && n <= 49999:
		kind = modiconHR
		regType = modbus.HOLDING_REGISTER
		protocolAddr = uint16(n - 40001)
	case n >= 400001 && n <= 465535:
		kind = modiconHR
		regType = modbus.HOLDING_REGISTER
		protocolAddr = uint16(n - 400001)
	default:
		return 0, 0, "", fmt.Errorf("invalid modicon addr %q (must be 0xxxx/1xxxx/3xxxx/4xxxx)", addr)
	}
	return regType, protocolAddr, kind, nil
}
