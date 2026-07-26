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

// Package dlt645 提供 DL/T 645-2007 多功能电能表通信协议的自实现帧编解码与采集节点。
//
// 帧格式（请求帧，主站→表）：
//
//	0x68 | A0-A5(6字节BCD地址,低字节在前) | 0x68 | C(控制码) | L(数据长度) | DATA(每字节+0x33) | CS | 0x16
//
// CS 为帧起始符到数据域末字节的算术和低 8 位。读数据控制码 0x11，正常应答 0x91，异常应答 0xD1。
// 数据标识 DI 配置按标准书写顺序 "DI3-DI2-DI1-DI0"（高字节在前，如 "02-01-01-00"），
// 上线传输时反转为低字节在前。
package dlt645

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	frameStart  = 0x68 // 帧起始符/地址域分隔符
	frameEnd    = 0x16 // 帧结束符
	ctrlRead    = 0x11 // 主站读数据
	ctrlWrite   = 0x14 // 主站写数据
	respMask    = 0x80 // 控制码 D7：从站应答标志
	errMask     = 0x40 // 控制码 D6：异常应答标志
	dataMask    = 0x33 // 数据域传输掩码
	addrLen     = 6    // 地址域字节数
	diLen       = 4    // 数据标识字节数
	minFrameLen = 12   // 最小帧长：68+A(6)+68+C+L+CS+16
)

// 异常应答错误码
var errCodes = map[byte]string{
	0x01: "other error",
	0x02: "rate count exceeded",
	0x03: "no data",
	0x04: "permission denied",
}

// Checksum 计算 CS：所有字节的算术和低 8 位。
func Checksum(b []byte) byte {
	var sum byte
	for _, c := range b {
		sum += c
	}
	return sum
}

// EncodeBCD 把 v 编码为 n 字节 BCD（高位数字在高字节，不足高位补 0）。
func EncodeBCD(v uint64, n int) []byte {
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		lo := byte(v % 10)
		v /= 10
		hi := byte(v % 10)
		v /= 10
		out[i] = hi<<4 | lo
	}
	return out
}

// DecodeBCD 解码 BCD 字节（高位数字在高字节）为无符号整数。
func DecodeBCD(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v*100 + uint64(c>>4)*10 + uint64(c&0x0F)
	}
	return v
}

// ParseAddr 解析 12 位十进制表地址串（如 "000000000001"，不足左补 0）为
// 6 字节地址域（A0 低字节在前）。
func ParseAddr(addr string) ([]byte, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("dlt645: empty meter address")
	}
	if len(addr) > addrLen*2 {
		return nil, fmt.Errorf("dlt645: meter address %q exceeds 12 digits", addr)
	}
	for _, c := range addr {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("dlt645: meter address %q has non-digit", addr)
		}
	}
	out := make([]byte, addrLen)
	// 从个位起每两位一字节，低字节在前
	for i, pos := 0, len(addr)-2; i < addrLen; i, pos = i+1, pos-2 {
		if pos >= 0 {
			out[i] = (addr[pos]-'0')<<4 | (addr[pos+1] - '0')
		}
	}
	return out, nil
}

// FormatAddr 把 6 字节地址域（A0 低字节在前）格式化为 12 位十进制串。
func FormatAddr(addr []byte) string {
	var sb strings.Builder
	for i := len(addr) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%02X", addr[i])
	}
	return sb.String()
}

// ParseDI 解析数据标识串（"DI3-DI2-DI1-DI0" 标准书写序或连写 8 位十六进制，如
// "02-01-01-00"/"02010100"）为线序字节 [DI0,DI1,DI2,DI3]（低字节在前）。
func ParseDI(s string) ([diLen]byte, error) {
	var di [diLen]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != diLen*2 {
		return di, fmt.Errorf("dlt645: invalid DI %q, expect DI3-DI2-DI1-DI0", s)
	}
	hi, err := hex.DecodeString(clean)
	if err != nil {
		return di, fmt.Errorf("dlt645: invalid DI %q: %v", s, err)
	}
	// 书写序 DI3..DI0 -> 线序 DI0..DI3
	for i := 0; i < diLen; i++ {
		di[i] = hi[diLen-1-i]
	}
	return di, nil
}

// FormatDI 把线序 DI 格式化为标准书写串 "DI3-DI2-DI1-DI0"。
func FormatDI(di [diLen]byte) string {
	return fmt.Sprintf("%02X-%02X-%02X-%02X", di[3], di[2], di[1], di[0])
}

// BuildReadFrame 构造读数据请求帧（控制码 0x11，数据域为 4 字节 DI）。
func BuildReadFrame(addr string, di []byte) ([]byte, error) {
	if len(di) != diLen {
		return nil, fmt.Errorf("dlt645: DI length %d, expect 4", len(di))
	}
	addrBytes, err := ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	return buildFrame(addrBytes, ctrlRead, di), nil
}

// BuildWriteFrame 构造写数据请求帧（控制码 0x14，数据域为 DI + 待写数据）。
func BuildWriteFrame(addr string, di, data []byte) ([]byte, error) {
	if len(di) != diLen {
		return nil, fmt.Errorf("dlt645: DI length %d, expect 4", len(di))
	}
	addrBytes, err := ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, diLen+len(data))
	payload = append(payload, di...)
	payload = append(payload, data...)
	return buildFrame(addrBytes, ctrlWrite, payload), nil
}

// buildFrame 组装完整帧：数据域逐字节 +0x33，末尾追加 CS 与 0x16。
func buildFrame(addrBytes []byte, ctrl byte, payload []byte) []byte {
	frame := make([]byte, 0, minFrameLen+len(payload))
	frame = append(frame, frameStart)
	frame = append(frame, addrBytes...)
	frame = append(frame, frameStart, ctrl, byte(len(payload)))
	for _, b := range payload {
		frame = append(frame, b+dataMask)
	}
	frame = append(frame, Checksum(frame), frameEnd)
	return frame
}

// parseFrame 解析完整帧，返回控制码、地址域、数据域（已逐字节 -0x33 还原）。
// 校验帧结构（长度/起始符/结束符）与 CS。
func parseFrame(frame []byte) (ctrl byte, addr, payload []byte, err error) {
	if len(frame) < minFrameLen {
		return 0, nil, nil, fmt.Errorf("dlt645: frame too short (%d bytes)", len(frame))
	}
	if frame[0] != frameStart {
		return 0, nil, nil, fmt.Errorf("dlt645: invalid frame start 0x%02X", frame[0])
	}
	if frame[7] != frameStart {
		return 0, nil, nil, fmt.Errorf("dlt645: invalid address separator 0x%02X", frame[7])
	}
	l := int(frame[9])
	if len(frame) != minFrameLen+l {
		return 0, nil, nil, fmt.Errorf("dlt645: frame length %d mismatch data length %d", len(frame), l)
	}
	if frame[len(frame)-1] != frameEnd {
		return 0, nil, nil, fmt.Errorf("dlt645: invalid frame end 0x%02X", frame[len(frame)-1])
	}
	if cs := Checksum(frame[:len(frame)-2]); cs != frame[len(frame)-2] {
		return 0, nil, nil, fmt.Errorf("dlt645: checksum mismatch: got 0x%02X, want 0x%02X", frame[len(frame)-2], cs)
	}
	raw := frame[10 : 10+l]
	payload = make([]byte, l)
	for i, b := range raw {
		payload[i] = b - dataMask
	}
	return frame[8], frame[1:7], payload, nil
}

// ParseResponse 解析从站应答帧，返回 DI 与应答数据（已减 0x33）。
// 非从站应答帧、异常应答（控制码 D6=1，数据域为 ERR 错误码）均返回 error。
func ParseResponse(frame []byte) (di, data []byte, err error) {
	ctrl, _, payload, err := parseFrame(frame)
	if err != nil {
		return nil, nil, err
	}
	if ctrl&respMask == 0 {
		return nil, nil, fmt.Errorf("dlt645: not a slave response (ctrl=0x%02X)", ctrl)
	}
	if ctrl&errMask != 0 {
		code := byte(0)
		if len(payload) > 0 {
			code = payload[0]
		}
		msg := errCodes[code]
		if msg == "" {
			msg = "unknown"
		}
		return nil, nil, fmt.Errorf("dlt645: abnormal response ERR=0x%02X (%s)", code, msg)
	}
	if len(payload) < diLen {
		return nil, nil, fmt.Errorf("dlt645: response data too short (%d bytes)", len(payload))
	}
	return payload[:diLen], payload[diLen:], nil
}
