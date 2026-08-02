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

// Frame HJ212 frame (HJ 212-2017): ##LLLL<QN=..;ST=..;CN=..;PW=..;MN=..;Flag=..;CP=&&...&&>CCCC\r\n
// LLLL=data segment length (decimal 4 digits), CCCC=CRC16 (hex 4 digits, checksum range is data segment).
type Frame struct {
	QN       string    // Request number (timestamp YYYYMMDDhhmmsszzz)
	ST       string    // System code (32=pollution source monitoring)
	CN       string    // Command code (2011=real-time data/2051=minute data/2061=hourly data/2031=daily data)
	PW       string    // Access password
	MN       string    // Device unique identifier
	Flag     string    // Flag (bit0=need response, bit1=has packet)
	DataTime time.Time // CP data collection time (default zero value)
	Points   []iot_points.Data
}

// Pollutant value statistical suffixes (non-numeric fields like Flag/SampleTime not output); Zs series are reduced concentrations (HJ 212-2017 flue gas)
var valueSuffixes = map[string]bool{
	"Rtd": true, "Avg": true, "Min": true, "Max": true, "Cou": true,
	"ZsRtd": true, "ZsAvg": true, "ZsMin": true, "ZsMax": true, "ZsCou": true,
}

// ParseFrame parses a complete HJ212 frame and validates CRC16; input may exclude \r\n ending.
func ParseFrame(data []byte) (*Frame, error) {
	s := strings.TrimSuffix(string(data), "\r\n")
	if !strings.HasPrefix(s, "##") || len(s) < 12 {
		return nil, errors.New("hj212: invalid frame prefix")
	}
	dataLen, err := strconv.Atoi(s[2:6])
	if err != nil {
		return nil, fmt.Errorf("hj212: invalid data length: %w", err)
	}
	if len(s) != dataLen+10 { // 4-digit length + data segment + 4-digit CRC
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

// parseSegment parses data segment: header fields + CP=// parseSegment parses data segment: header fields + CP=&&...&& content.// parseSegment parses data segment: header fields + CP=&&...&& content....// parseSegment parses data segment: header fields + CP=&&...&& content.// parseSegment parses data segment: header fields + CP=&&...&& content. content.
func parseSegment(seg string) (*Frame, error) {
	cpIdx := strings.Index(seg, "CP=&&")
	if cpIdx < 0 {
		return nil, errors.New("hj212: CP segment missing")
	}
	end := strings.LastIndex(seg, "&&")
	// Closing && must come after CP=&& (which occupies cpIdx..cpIdx+4).
	if end < cpIdx+5 {
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

// parseFactors parses factor group: a34004-Rtd=2.3,a34004-Flag=N (only numeric statistical suffix outputs Data).
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
// Statistical suffix merged into Name
		pointName := name
		switch suffix {
		case "Rtd": // Measured real-time value as default semantics, keep bare factor code
		case "ZsRtd": // Converted real-time value, distinguished by -Zs prefix
			pointName = name + "-Zs"
		default:
			pointName = name + "-" + suffix
		}
		out = append(out, iot_points.Data{Name: pointName, Value: num})
	}
	return out
}

// crc16 HJ 212-2017 Annex A CRC16 checksum (equivalent to CRC-16/MODBUS: initial 0xFFFF, polynomial 0xA001).
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

// maxDataLen data segment length upper limit (standard specifies ≤1024)
const maxDataLen = 2048

// extractFrame extracts first complete frame from receive buffer.
// Returns (frame, consumed bytes, success): on failure used>0 means caller should discard that part of buffer and retry.
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
		return nil, 2, false // Skip illegal ## prefix
	}
	total := dataLen + 12
	if len(buf) < total {
		return nil, 0, false
	}
	return buf[:total], total, true
}

// BuildAckFrame constructs HJ 212-2017 acknowledgment response frame (ST=91, CN=9014, QnRtn=1).
// Format: ##LLLL<QN=..;ST=91;CN=9014;PW=..;MN=..;Flag=0;CP=&&QnRtn=1&&>CCCC\r\n
func BuildAckFrame(req *Frame) []byte {
	seg := fmt.Sprintf("QN=%s;ST=91;CN=9014;PW=%s;MN=%s;Flag=0;CP=&&QnRtn=1&&", req.QN, req.PW, req.MN)
	crc := crc16(seg)
	return []byte(fmt.Sprintf("##%04d%s%04X\r\n", len(seg), seg, crc))
}
