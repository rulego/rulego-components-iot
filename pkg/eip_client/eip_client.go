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

// Package eipclient 封装 danomagnum/gologix，提供罗克韦尔 ControlLogix/
// CompactLogix PLC 通过 EtherNet/IP (CIP) 的连接、批量标签读写。
//
// 仅支持 CIP 设备（ControlLogix/CompactLogix/Micro820），不支持 PLC5/SLC/MicroLogix(PCCC)。
// 点位需指定 type。
package eipclient

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/danomagnum/gologix"
	"github.com/rulego/rulego/api/types"
)

// EipDataMsgType EIP 数据消息类型
const EipDataMsgType = "EIP_DATA"

// Data 统一的点位输出契约
type Data struct {
	Name      string      `json:"name"`
	Address   string      `json:"address"` // tag 名
	Value     interface{} `json:"value"`
	Type      string      `json:"type"`
	Quality   string      `json:"quality"`
	Timestamp time.Time   `json:"timestamp"`
}

// Point EIP 点位定义，读/写共用
type Point struct {
	Name  string `json:"name"`            // 点位名称
	Tag   string `json:"tag"`             // 符号标签名，如 MyDB.Temperature
	Type  string `json:"type"`            // BOOL/INT/DINT/REAL/STRING/...
	Value string `json:"value,omitempty"` // 仅写入：值的字符串形式
}

// ConfigProp EIP 连接配置接口
type ConfigProp interface {
	GetServer() string // host
	GetSlot() int      // CPU 槽位，自动生成 CIP 路径
	GetPath() string   // 可选：手动覆盖 CIP 路径，如 1,0
	GetTimeout() int   // 秒
}

// Holder EIP 客户端配置持有者
type Holder struct {
	Config ConfigProp
}

// DefaultHolder 默认配置
func DefaultHolder(c ConfigProp) *Holder {
	return &Holder{Config: c}
}

// NewClient 创建并连接 gologix 客户端
func (h *Holder) NewClient() (*gologix.Client, error) {
	if h.Config == nil {
		return nil, errors.New("eip config is nil")
	}
	client := gologix.NewClient(h.Config.GetServer())
	// CIP 路径优先级：配置 path > 按 slot 自动生成
	if path := strings.TrimSpace(h.Config.GetPath()); path != "" {
		p, err := gologix.ParsePath(path)
		if err != nil {
			return nil, fmt.Errorf("parse path %q error: %w", path, err)
		}
		client.Controller.Path = p
	} else {
		slot := h.Config.GetSlot()
		p, err := gologix.ParsePath(fmt.Sprintf("1,%d", slot))
		if err != nil {
			return nil, fmt.Errorf("auto slot path \"1,%d\": %w", slot, err)
		}
		client.Controller.Path = p
	}
	if t := h.Config.GetTimeout(); t > 0 {
		client.SocketTimeout = time.Duration(t) * time.Second
	}
	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

// ReadPoints 批量读取标签。单个标签失败不影响其它（标记 quality=bad）。
func ReadPoints(client *gologix.Client, points []Point, logger types.Logger) ([]Data, error) {
	if client == nil {
		return nil, errors.New("eip client is nil")
	}
	results := make([]Data, 0, len(points))
	failCount := 0
	var lastErr error
	for _, p := range points {
		d := Data{
			Name:      p.Name,
			Address:   p.Tag,
			Type:      strings.ToUpper(strings.TrimSpace(p.Type)),
			Timestamp: time.Now(),
		}
		val, err := readTag(client, p.Tag, p.Type)
		if err != nil {
			d.Quality = "bad"
			failCount++
			lastErr = err
			if logger != nil {
				logger.Errorf("[EIP] read %s error: %v", p.Tag, err)
			}
		} else {
			d.Quality = "good"
			d.Value = val
		}
		results = append(results, d)
	}
	// 全部点位失败：疑似连接级错误，返回 error
	if len(points) > 0 && failCount == len(points) {
		return results, fmt.Errorf("all %d points failed (possible connection error): %w", failCount, lastErr)
	}
	return results, nil
}

// readTag 按 type 读取单个 tag 到对应类型指针
func readTag(client *gologix.Client, tag, typ string) (interface{}, error) {
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "BOOL":
		var v bool
		err := client.Read(tag, &v)
		return v, err
	case "BYTE", "SINT", "USINT":
		var v byte
		err := client.Read(tag, &v)
		return v, err
	case "INT", "INT16":
		var v int16
		err := client.Read(tag, &v)
		return v, err
	case "UINT", "WORD", "UINT16":
		var v uint16
		err := client.Read(tag, &v)
		return v, err
	case "DINT", "INT32":
		var v int32
		err := client.Read(tag, &v)
		return v, err
	case "UDINT", "DWORD", "UINT32":
		var v uint32
		err := client.Read(tag, &v)
		return v, err
	case "LINT", "INT64":
		var v int64
		err := client.Read(tag, &v)
		return v, err
	case "ULINT", "UINT64":
		var v uint64
		err := client.Read(tag, &v)
		return v, err
	case "REAL", "FLOAT":
		var v float32
		err := client.Read(tag, &v)
		return v, err
	case "LREAL", "DOUBLE":
		var v float64
		err := client.Read(tag, &v)
		return v, err
	case "STRING":
		var v string
		err := client.Read(tag, &v)
		return v, err
	}
	return nil, fmt.Errorf("unsupported eip type: %q (supported: BOOL/INT/DINT/REAL/STRING/...)", typ)
}

// WritePoints 批量写入标签。任一失败立即返回错误。
func WritePoints(client *gologix.Client, points []Point) error {
	if client == nil {
		return errors.New("eip client is nil")
	}
	for _, p := range points {
		val, err := encodeValue(p.Value, p.Type)
		if err != nil {
			return fmt.Errorf("encode %s error: %w", p.Tag, err)
		}
		if err := client.Write(p.Tag, val); err != nil {
			return fmt.Errorf("write %s error: %w", p.Tag, err)
		}
	}
	return nil
}

// encodeValue 按 type 把值的字符串形式解析为 Go 值（供 Write）
func encodeValue(value, typ string) (interface{}, error) {
	v := strings.TrimSpace(value)
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "BOOL":
		return parseBoolValue(v)
	case "BYTE", "SINT", "USINT":
		n, err := strconv.ParseUint(v, 0, 8)
		return byte(n), err
	case "INT", "INT16":
		n, err := strconv.ParseInt(v, 0, 16)
		return int16(n), err
	case "UINT", "WORD", "UINT16":
		n, err := strconv.ParseUint(v, 0, 16)
		return uint16(n), err
	case "DINT", "INT32":
		n, err := strconv.ParseInt(v, 0, 32)
		return int32(n), err
	case "UDINT", "DWORD", "UINT32":
		n, err := strconv.ParseUint(v, 0, 32)
		return uint32(n), err
	case "LINT", "INT64":
		n, err := strconv.ParseInt(v, 0, 64)
		return int64(n), err
	case "ULINT", "UINT64":
		n, err := strconv.ParseUint(v, 0, 64)
		return uint64(n), err
	case "REAL", "FLOAT":
		n, err := strconv.ParseFloat(v, 32)
		return float32(n), err
	case "LREAL", "DOUBLE":
		n, err := strconv.ParseFloat(v, 64)
		return n, err
	case "STRING":
		return v, nil
	}
	return nil, fmt.Errorf("unsupported eip type: %q", typ)
}

// parseBoolValue 解析 bool 值字符串（支持 true/false/0/1）
func parseBoolValue(s string) (bool, error) {
	s = strings.TrimSpace(s)
	if b, err := strconv.ParseBool(s); err == nil {
		return b, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n != 0, nil
	}
	return false, fmt.Errorf("invalid bool value: %q", s)
}
