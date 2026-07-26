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

package iot_points

import "time"

// 采集节点共享常量
const (
	// DefaultMaxRetries 连接级失败后的最大重试次数
	DefaultMaxRetries = 3
	// ReconnectDelay 重连前等待
	ReconnectDelay = 200 * time.Millisecond
	// DefaultTimeoutSec 默认请求超时（秒）
	DefaultTimeoutSec = 5
)

// 通用数据类型枚举（协议无关）。各 driver 负责映射到协议原生类型。
const (
	TypeBool    = "BOOL"
	TypeInt16   = "INT16"
	TypeUint16  = "UINT16"
	TypeInt32   = "INT32"
	TypeUint32  = "UINT32"
	TypeInt64   = "INT64"
	TypeUint64  = "UINT64"
	TypeFloat32 = "FLOAT32"
	TypeFloat64 = "FLOAT64"
	TypeString  = "STRING"
)

// Point 统一采集点位（配置层，字段支持 ${msg.xx}/${metadata.xx} 模板）。
// Addr 为协议寻址串，由各 driver 解析（如 s7 "DB1.DBD0"/"M0.1"、modbus Modicon "40001"、
// opcua NodeID "ns=2;s=Temperature"、snmp OID "1.3.6.1..."、mc "D100"、fins "CIO100"/"D100.5"）。
type Point struct {
	Name   string  `json:"name"`             // 点位名，输出时作为 Data.Name（下游取值的键）
	Addr   string  `json:"addr"`             // 协议寻址串，由各 driver 解析（格式见包注释）
	Type   string  `json:"type"`             // 数据类型，取 TypeXxx 枚举；留空按协议默认类型
	Scale  float64 `json:"scale,omitempty"`  // 工程量缩放系数，0 表示不缩放（见 ApplyScale）
	Offset float64 `json:"offset,omitempty"` // 工程量偏移量，0 表示不偏移
	Endian string  `json:"endian,omitempty"` // 字节序 ABCD/CDAB/BADC/DCBA，仅多寄存器类型生效
	Value  string  `json:"value,omitempty"`  // 写入值（字符串形式，driver 按 Type 解析）
}

// Data 采集结果（单点）。读节点输出 []Data，单点失败标 Error 而非整批失败。
type Data struct {
	Name      string      `json:"name"`                // 点位名，对应 Point.Name
	Value     interface{} `json:"value"`               // 读到的值（协议原生类型）；坏点时为空
	Timestamp int64       `json:"timestamp,omitempty"` // 采集时间戳（ns），0 表示协议未提供
	Error     string      `json:"error,omitempty"`     // 单点错误信息，空表示成功
}

// ApplyScale 工程量转换：eng = raw*scale + offset。
// Scale/Offset 均为 0 时原样返回 raw；注意 scale=0 而 offset≠0 时结果为 offset（raw 被丢弃，
// 如需仅平移应显式配 scale=1）。
func ApplyScale(raw float64, p Point) float64 {
	if p.Scale == 0 && p.Offset == 0 {
		return raw
	}
	return raw*p.Scale + p.Offset
}

// RenderPoint 渲染 Point 的字符串字段模板（Name/Addr/Type/Endian/Value），Scale/Offset 透传。
// 由节点层用 ctx+msg 构造的 env 调用，driver 只接渲染后的 Point（无 ${}）。
func RenderPoint(p Point, env map[string]interface{}) Point {
	return Point{
		Name:   RenderTemplate(p.Name, env),
		Addr:   RenderTemplate(p.Addr, env),
		Type:   RenderTemplate(p.Type, env),
		Scale:  p.Scale,
		Offset: p.Offset,
		Endian: RenderTemplate(p.Endian, env),
		Value:  RenderTemplate(p.Value, env),
	}
}
