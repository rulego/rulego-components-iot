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

// Package s7client 封装 robinson/gos7，提供西门子 S7 PLC 的连接、
// 批量点位读写与类型解析。输出统一契约 Data 供 rulego 下游节点处理。
//
// 仅支持经典 S7comm（S7-200SMART/300/400/1200/1500 的 PG/OP 通信）。
// 前提：TIA Portal 需开启「允许 PUT/GET 通信」、关闭数据块的「优化的块访问」。
package s7client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/robinson/gos7"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// S7DataMsgType S7 数据消息类型
const S7DataMsgType = "S7_DATA"

// S7 区域 ID（gos7 内部小写未导出，按协议常量值重新定义）
const (
	areaDB = 0x84 // 数据块 Data Block
	areaM  = 0x83 // 标志区 Markers
	areaI  = 0x81 // 输入 Inputs
	areaQ  = 0x82 // 输出 Outputs
)

// Data 统一的点位输出契约
type Data struct {
	Name      string      `json:"name"`
	Address   string      `json:"address"`
	Value     interface{} `json:"value"`
	Type      string      `json:"type"`
	Quality   string      `json:"quality"`
	Timestamp time.Time   `json:"timestamp"`
}

// Point S7 点位定义，读/写共用
type Point struct {
	Name      string `json:"name"`                // 点位名称（输出带上，方便下游取值）
	Area      string `json:"area"`                // DB/M/I/Q
	DbNumber  int    `json:"dbNumber"`            // 仅 area=DB 时有效
	Address   int    `json:"address"`             // 字节偏移
	Type      string `json:"type"`                // BOOL/BYTE/INT/WORD/DINT/DWORD/REAL/LREAL/STRING
	BitOffset int    `json:"bitOffset,omitempty"` // 仅 type=BOOL 时有效，0-7
	Count     int    `json:"count,omitempty"`     // 数量，默认1；STRING 忽略
	StringLen int    `json:"stringLen,omitempty"` // STRING 声明最大长度，默认 254
	Value     string `json:"value,omitempty"`     // 仅写入：值的字符串形式
}

// ConfigProp S7 连接配置接口
type ConfigProp interface {
	GetServer() string // host:port
	GetRack() int
	GetSlot() int
	GetTimeout() int // 秒
}

// Holder S7 客户端配置持有者
type Holder struct {
	Config ConfigProp
}

// DefaultHolder 默认配置
func DefaultHolder(c ConfigProp) *Holder {
	return &Holder{Config: c}
}

// NewHandler 创建并连接 S7 TCP 处理器（连接的持有者，由 SharedNode 复用）
func (h *Holder) NewHandler() (*gos7.TCPClientHandler, error) {
	if h.Config == nil {
		return nil, errors.New("s7 config is nil")
	}
	timeout := h.Config.GetTimeout()
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	host, port, err := iot_points.ParseServer(h.Config.GetServer(), 102)
	if err != nil {
		return nil, err
	}
	handler := gos7.NewTCPClientHandler(net.JoinHostPort(host, strconv.Itoa(port)), h.Config.GetRack(), h.Config.GetSlot())
	handler.Timeout = time.Duration(timeout) * time.Second
	handler.IdleTimeout = time.Duration(timeout) * time.Second
	if err := handler.Connect(); err != nil {
		return nil, err
	}
	return handler, nil
}

// parseArea 区域字符串 -> 区域 ID
func parseArea(area string) (int, error) {
	switch strings.ToUpper(strings.TrimSpace(area)) {
	case "DB":
		return areaDB, nil
	case "M":
		return areaM, nil
	case "I":
		return areaI, nil
	case "Q":
		return areaQ, nil
	}
	return 0, fmt.Errorf("unsupported s7 area: %q (supported: DB/M/I/Q)", area)
}

// sizeOfType 单个值占用的字节数
func sizeOfType(t string) int {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "BOOL", "BYTE":
		return 1
	case "INT", "WORD":
		return 2
	case "DINT", "DWORD", "REAL":
		return 4
	case "LREAL":
		return 8
	case "STRING":
		return 256
	}
	return 0
}

// stringMaxLen STRING 点位的声明最大长度，未声明（<=0）时取默认 254。
func stringMaxLen(p Point) int {
	if p.StringLen > 0 {
		return p.StringLen
	}
	return 254
}

// formatAddr 生成可读地址串
func formatAddr(p Point) string {
	area := strings.ToUpper(strings.TrimSpace(p.Area))
	if area == "DB" {
		base := fmt.Sprintf("DB%d.%d", p.DbNumber, p.Address)
		if strings.ToUpper(p.Type) == "BOOL" {
			return fmt.Sprintf("%s.%d", base, p.BitOffset)
		}
		return base
	}
	if strings.ToUpper(p.Type) == "BOOL" {
		return fmt.Sprintf("%s%d.%d", area, p.Address, p.BitOffset)
	}
	return fmt.Sprintf("%s%d", area, p.Address)
}

// ReadPoints 批量读取点位。单个点位失败不影响其它点位（标记 quality=bad）。
func ReadPoints(handler *gos7.TCPClientHandler, points []Point, logger types.Logger) ([]Data, error) {
	if handler == nil {
		return nil, errors.New("s7 handler is nil")
	}
	client := gos7.NewClient(handler)
	results := make([]Data, 0, len(points))
	failCount := 0
	var lastErr error
	for _, p := range points {
		d := Data{
			Name:      p.Name,
			Address:   formatAddr(p),
			Type:      strings.ToUpper(strings.TrimSpace(p.Type)),
			Timestamp: time.Now(),
		}
		val, err := readPoint(client, p)
		if err != nil {
			d.Quality = "bad"
			failCount++
			lastErr = err
			if logger != nil {
				logger.Errorf("[S7] read %s error: %v", d.Address, err)
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

// readPoint 读取单个点位
func readPoint(client gos7.Client, p Point) (interface{}, error) {
	area, err := parseArea(p.Area)
	if err != nil {
		return nil, err
	}
	t := strings.ToUpper(strings.TrimSpace(p.Type))
	ts := sizeOfType(t)
	if ts == 0 {
		return nil, fmt.Errorf("unsupported s7 type: %q", p.Type)
	}
	count := p.Count
	if count <= 0 {
		count = 1
	}
	sizeBytes := ts
	if t == "STRING" {
		sizeBytes = stringMaxLen(p) + 2
	} else {
		sizeBytes = ts * count
	}
	buf := make([]byte, sizeBytes)

	switch area {
	case areaDB:
		err = client.AGReadDB(p.DbNumber, p.Address, sizeBytes, buf)
	case areaM:
		err = client.AGReadMB(p.Address, sizeBytes, buf)
	case areaI:
		err = client.AGReadEB(p.Address, sizeBytes, buf)
	case areaQ:
		err = client.AGReadAB(p.Address, sizeBytes, buf)
	}
	if err != nil {
		return nil, err
	}
	if count > 1 && t != "BOOL" && t != "STRING" {
		return decodeArray(buf, t, count)
	}
	return decodeScalar(buf, t, p.BitOffset)
}

// decodeScalar 解析单个值（大端，S7 默认字节序）
func decodeScalar(buf []byte, t string, bitOffset int) (interface{}, error) {
	switch t {
	case "BOOL":
		off := bitOffset
		if off < 0 || off > 7 {
			off = 0
		}
		if len(buf) < 1 {
			return false, nil
		}
		return (buf[0]>>uint(off))&1 == 1, nil
	case "BYTE":
		if len(buf) < 1 {
			return byte(0), nil
		}
		return buf[0], nil
	case "INT":
		if len(buf) < 2 {
			return int16(0), nil
		}
		return int16(binary.BigEndian.Uint16(buf)), nil
	case "WORD":
		if len(buf) < 2 {
			return uint16(0), nil
		}
		return binary.BigEndian.Uint16(buf), nil
	case "DINT":
		if len(buf) < 4 {
			return int32(0), nil
		}
		return int32(binary.BigEndian.Uint32(buf)), nil
	case "DWORD":
		if len(buf) < 4 {
			return uint32(0), nil
		}
		return binary.BigEndian.Uint32(buf), nil
	case "REAL":
		if len(buf) < 4 {
			return float32(0), nil
		}
		return math.Float32frombits(binary.BigEndian.Uint32(buf)), nil
	case "LREAL":
		if len(buf) < 8 {
			return float64(0), nil
		}
		return math.Float64frombits(binary.BigEndian.Uint64(buf)), nil
	case "STRING":
		// S7 string: buf[0]=maxLen, buf[1]=actualLen, buf[2:2+actualLen]=chars
		if len(buf) < 2 {
			return "", nil
		}
		actual := int(buf[1])
		if 2+actual > len(buf) {
			actual = len(buf) - 2
		}
		if actual < 0 {
			actual = 0
		}
		return string(buf[2 : 2+actual]), nil
	}
	return nil, fmt.Errorf("unsupported type: %s", t)
}

// decodeArray 解析数组（count 个同类型值）
func decodeArray(buf []byte, t string, count int) (interface{}, error) {
	ts := sizeOfType(t)
	arr := make([]interface{}, 0, count)
	for i := 0; i < count; i++ {
		end := (i + 1) * ts
		if end > len(buf) {
			break
		}
		v, err := decodeScalar(buf[i*ts:end], t, 0)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
	return arr, nil
}

// WritePoints 批量写入点位。任一点位失败立即返回错误。
func WritePoints(handler *gos7.TCPClientHandler, points []Point) error {
	if handler == nil {
		return errors.New("s7 handler is nil")
	}
	client := gos7.NewClient(handler)
	for _, p := range points {
		if err := writePoint(client, p); err != nil {
			return fmt.Errorf("write %s error: %w", formatAddr(p), err)
		}
	}
	return nil
}

func writePoint(client gos7.Client, p Point) error {
	area, err := parseArea(p.Area)
	if err != nil {
		return err
	}
	t := strings.ToUpper(strings.TrimSpace(p.Type))
	if t == "BOOL" {
		return writeBit(client, area, p)
	}
	buf, err := encodeScalar(p.Value, t, p.StringLen)
	if err != nil {
		return err
	}
	switch area {
	case areaDB:
		return client.AGWriteDB(p.DbNumber, p.Address, len(buf), buf)
	case areaM:
		return client.AGWriteMB(p.Address, len(buf), buf)
	case areaI:
		return client.AGWriteEB(p.Address, len(buf), buf)
	case areaQ:
		return client.AGWriteAB(p.Address, len(buf), buf)
	}
	return fmt.Errorf("unsupported area: %s", p.Area)
}

// writeBit 位写入：读-改-写
func writeBit(client gos7.Client, area int, p Point) error {
	buf := make([]byte, 1)
	switch area {
	case areaDB:
		if err := client.AGReadDB(p.DbNumber, p.Address, 1, buf); err != nil {
			return err
		}
	case areaM:
		if err := client.AGReadMB(p.Address, 1, buf); err != nil {
			return err
		}
	case areaI:
		if err := client.AGReadEB(p.Address, 1, buf); err != nil {
			return err
		}
	case areaQ:
		if err := client.AGReadAB(p.Address, 1, buf); err != nil {
			return err
		}
	default:
		return fmt.Errorf("bit write unsupported for area: %s", p.Area)
	}
	b, err := parseBoolValue(p.Value)
	if err != nil {
		return err
	}
	off := uint(p.BitOffset)
	if off > 7 {
		off = 0
	}
	if b {
		buf[0] |= 1 << off
	} else {
		buf[0] &^= 1 << off
	}
	switch area {
	case areaDB:
		return client.AGWriteDB(p.DbNumber, p.Address, 1, buf)
	case areaM:
		return client.AGWriteMB(p.Address, 1, buf)
	case areaI:
		return client.AGWriteEB(p.Address, 1, buf)
	case areaQ:
		return client.AGWriteAB(p.Address, 1, buf)
	}
	return nil
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

// encodeScalar 将值的字符串形式编码为字节（大端，S7 默认）
func encodeScalar(value string, t string, stringLen int) ([]byte, error) {
	v := strings.TrimSpace(value)
	switch t {
	case "BYTE":
		n, err := strconv.ParseUint(v, 0, 8)
		if err != nil {
			return nil, err
		}
		return []byte{byte(n)}, nil
	case "INT":
		n, err := strconv.ParseInt(v, 0, 16)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(n))
		return buf, nil
	case "WORD":
		n, err := strconv.ParseUint(v, 0, 16)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(n))
		return buf, nil
	case "DINT":
		n, err := strconv.ParseInt(v, 0, 32)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(n))
		return buf, nil
	case "DWORD":
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(n))
		return buf, nil
	case "REAL":
		n, err := strconv.ParseFloat(v, 32)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, math.Float32bits(float32(n)))
		return buf, nil
	case "LREAL":
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, math.Float64bits(n))
		return buf, nil
	case "STRING":
		maxLen := stringLen
		if maxLen <= 0 {
			maxLen = 254
		}
		content := []byte(v)
		if len(content) > maxLen {
			content = content[:maxLen]
		}
		buf := make([]byte, maxLen+2)
		buf[0] = byte(maxLen)
		buf[1] = byte(len(content))
		copy(buf[2:], content)
		return buf, nil
	}
	return nil, fmt.Errorf("unsupported type for encode: %s", t)
}
