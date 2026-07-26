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

package hj212

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
)

// Frame HJ212 帧（HJ 212-2017）：##LLLL<QN=..;ST=..;CN=..;PW=..;MN=..;Flag=..;CP=&&...&&>CCCC\r\n
// LLLL=数据段长度（十进制 4 位），CCCC=CRC16（十六进制 4 位，校验范围为数据段）。
type Frame struct {
	QN       string    // 请求编号（时间戳 YYYYMMDDhhmmsszzz）
	ST       string    // 系统编码（32=污染源监控）
	CN       string    // 命令编码（2011=实时数据/2051=分钟数据/2061=小时数据/2031=日数据）
	PW       string    // 访问密码
	MN       string    // 设备唯一标识
	Flag     string    // 标志位（bit0=需要应答，bit1=有分包）
	DataTime time.Time // CP 数据采集时间（缺省为零值）
	Points   []iot_points.Data
}

// 污染物数值统计后缀（其余如 Flag/SampleTime 非数值字段不输出）；Zs 系列为折算浓度（HJ 212-2017 烟气）
var valueSuffixes = map[string]bool{
	"Rtd": true, "Avg": true, "Min": true, "Max": true, "Cou": true,
	"ZsRtd": true, "ZsAvg": true, "ZsMin": true, "ZsMax": true, "ZsCou": true,
}

// ParseFrame 解析一条完整 HJ212 帧并校验 CRC16；入参可不含 \r\n 结尾。
func ParseFrame(data []byte) (*Frame, error) {
	s := strings.TrimSuffix(string(data), "\r\n")
	if !strings.HasPrefix(s, "##") || len(s) < 12 {
		return nil, errors.New("hj212: invalid frame prefix")
	}
	dataLen, err := strconv.Atoi(s[2:6])
	if err != nil {
		return nil, fmt.Errorf("hj212: invalid data length: %w", err)
	}
	if len(s) != dataLen+10 { // 4 位长度 + 数据段 + 4 位 CRC
		return nil, fmt.Errorf("hj212: length mismatch: declared %d, actual %d", dataLen, len(s)-10)
	}
	seg := s[6 : 6+dataLen]
	crc, err := strconv.ParseUint(s[6+dataLen:], 16, 16)
	if err != nil {
		return nil, fmt.Errorf("hj212: invalid crc: %w", err)
	}
	if uint16(crc) != crc16(seg) {
		return nil, errors.New("hj212: crc check failed")
	}
	return parseSegment(seg)
}

// parseSegment 解析数据段：头部字段 + CP=&&...&& 内容。
func parseSegment(seg string) (*Frame, error) {
	cpIdx := strings.Index(seg, "CP=&&")
	if cpIdx < 0 {
		return nil, errors.New("hj212: CP segment missing")
	}
	end := strings.LastIndex(seg, "&&")
	if end <= cpIdx {
		return nil, errors.New("hj212: malformed CP segment")
	}
	f := &Frame{Points: []iot_points.Data{}}
	for _, field := range strings.Split(seg[:cpIdx], ";") {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch k {
		case "QN":
			f.QN = v
		case "ST":
			f.ST = v
		case "CN":
			f.CN = v
		case "PW":
			f.PW = v
		case "MN":
			f.MN = v
		case "Flag":
			f.Flag = v
		}
	}
	for _, item := range strings.Split(seg[cpIdx+5:end], ";") {
		if item == "" {
			continue
		}
		if v, ok := strings.CutPrefix(item, "DataTime="); ok {
			if t, err := time.ParseInLocation("20060102150405", v, time.Local); err == nil {
				f.DataTime = t
			}
			continue
		}
		f.Points = append(f.Points, parseFactors(item)...)
	}
	var ts int64
	if !f.DataTime.IsZero() {
		ts = f.DataTime.UnixNano()
	}
	for i := range f.Points {
		f.Points[i].Timestamp = ts
	}
	return f, nil
}

// parseFactors 解析因子组：a34004-Rtd=2.3,a34004-Flag=N（仅数值统计后缀输出 Data）。
func parseFactors(item string) []iot_points.Data {
	var out []iot_points.Data
	for _, part := range strings.Split(item, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name, suffix, found := strings.Cut(k, "-")
		if !found || !valueSuffixes[suffix] {
			continue
		}
		num, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		// 统计后缀并入 Name
		pointName := name
		switch suffix {
		case "Rtd": // 实测实时值为默认语义，保持裸因子码
		case "ZsRtd": // 折算实时值以 -Zs 与实测区分
			pointName = name + "-Zs"
		default:
			pointName = name + "-" + suffix
		}
		out = append(out, iot_points.Data{Name: pointName, Value: num})
	}
	return out
}

// crc16 HJ 212-2017 附录A CRC16 校验（等同 CRC-16/MODBUS：初值 0xFFFF，多项式 0xA001）。
func crc16(s string) uint16 {
	var crc uint16 = 0xFFFF
	for i := 0; i < len(s); i++ {
		crc ^= uint16(s[i])
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// maxDataLen 数据段长度上限（标准规定 ≤1024）
const maxDataLen = 2048

// extractFrame 从接收缓冲提取首条完整帧。
// 返回 (帧, 消耗的字节数, 是否提取成功)：失败时 used>0 表示调用方应丢弃该部分缓冲后重试。
func extractFrame(buf []byte) (frame []byte, used int, ok bool) {
	start := bytes.Index(buf, []byte("##"))
	if start < 0 {
		return nil, len(buf), false
	}
	if start > 0 {
		return nil, start, false
	}
	if len(buf) < 6 {
		return nil, 0, false
	}
	dataLen, err := strconv.Atoi(string(buf[2:6]))
	if err != nil || dataLen <= 0 || dataLen > maxDataLen {
		return nil, 2, false // 跳过非法 ## 前缀
	}
	total := dataLen + 12
	if len(buf) < total {
		return nil, 0, false
	}
	return buf[:total], total, true
}

// BuildAckFrame 构造 HJ 212-2017 确认应答帧（ST=91, CN=9014, QnRtn=1）。
// 格式：##LLLL<QN=..;ST=91;CN=9014;PW=..;MN=..;Flag=0;CP=&&QnRtn=1&&>CCCC\r\n
func BuildAckFrame(req *Frame) []byte {
	seg := fmt.Sprintf("QN=%s;ST=91;CN=9014;PW=%s;MN=%s;Flag=0;CP=&&QnRtn=1&&", req.QN, req.PW, req.MN)
	crc := crc16(seg)
	return []byte(fmt.Sprintf("##%04d%s%04X\r\n", len(seg), seg, crc))
}
