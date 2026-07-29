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

// Package snmpclient 封装 gosnmp/gosnmp，提供 SNMP（v1/v2c/v3）的连接、
// OID 批量读取（Get/Walk）、写入（Set）与 PDU 类型解析。
// 输出统一契约 Data 供 rulego 下游节点处理。
package snmpclient

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// SnmpDataMsgType SNMP 数据消息类型
const SnmpDataMsgType = "SNMP_DATA"

// Data 统一的点位输出契约
type Data struct {
	Name      string      `json:"name"`
	Address   string      `json:"address"` // OID
	Value     interface{} `json:"value"`
	Type      string      `json:"type"` // SNMP 类型字符串
	Quality   string      `json:"quality"`
	Timestamp time.Time   `json:"timestamp"`
}

// Point SNMP 点位定义，读/写共用
type Point struct {
	Name  string `json:"name"`            // 点位名称
	OID   string `json:"oid"`             // OID，如 1.3.6.1.2.1.1.5.0
	Op    string `json:"op,omitempty"`    // 读操作：get(默认)/walk；write 忽略
	Type  string `json:"type,omitempty"`  // 仅写入：值类型（Integer/OctetString/...）
	Value string `json:"value,omitempty"` // 仅写入：值的字符串形式
}

// ConfigProp SNMP 连接配置接口
type ConfigProp interface {
	GetServer() string        // host or host:port，默认端口 161
	GetVersion() string       // v1/v2c/v3
	GetCommunity() string     // v1/v2c community
	GetTimeout() int          // 秒
	GetSecurityLevel() string // v3: noAuthNoPriv/authNoPriv/authPriv
	GetUsername() string      // v3
	GetAuthProtocol() string  // v3: None/MD5/SHA/SHA224/SHA256/SHA384/SHA512
	GetAuthPassword() string  // v3
	GetPrivProtocol() string  // v3: None/DES/AES/AES192/AES256
	GetPrivPassword() string  // v3
}

// Holder SNMP 客户端配置持有者
type Holder struct {
	Config ConfigProp
}

// DefaultHolder 默认配置
func DefaultHolder(c ConfigProp) *Holder {
	return &Holder{Config: c}
}

// NewClient 创建并连接 SNMP 客户端
func (h *Holder) NewClient() (*gosnmp.GoSNMP, error) {
	if h.Config == nil {
		return nil, errors.New("snmp config is nil")
	}
	target, port, err := iot_points.ParseServer(h.Config.GetServer(), 161)
	if err != nil {
		return nil, err
	}
	timeout := h.Config.GetTimeout()
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	version, err := parseVersion(h.Config.GetVersion())
	if err != nil {
		return nil, err
	}
	g := &gosnmp.GoSNMP{
		Target:    target,
		Port:      uint16(port),
		Community: h.Config.GetCommunity(),
		Version:   version,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   3,
		MaxOids:   60,
	}
	if version == gosnmp.Version3 {
		if err := applyV3(g, h.Config); err != nil {
			return nil, err
		}
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

// parseVersion 版本字符串 -> gosnmp.SnmpVersion
func parseVersion(s string) (gosnmp.SnmpVersion, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "v2c", "v2", "2c":
		return gosnmp.Version2c, nil
	case "v1", "1":
		return gosnmp.Version1, nil
	case "v3", "3":
		return gosnmp.Version3, nil
	}
	return 0, fmt.Errorf("unsupported snmp version: %q", s)
}

// applyV3 配置 SNMPv3 USM 安全参数
func applyV3(g *gosnmp.GoSNMP, c ConfigProp) error {
	level, err := parseSecurityLevel(c.GetSecurityLevel())
	if err != nil {
		return err
	}
	g.MsgFlags = level
	g.SecurityParameters = &gosnmp.UsmSecurityParameters{
		UserName:                 c.GetUsername(),
		AuthenticationPassphrase: c.GetAuthPassword(),
		PrivacyPassphrase:        c.GetPrivPassword(),
		AuthenticationProtocol:   parseAuthProtocol(c.GetAuthProtocol()),
		PrivacyProtocol:          parsePrivProtocol(c.GetPrivProtocol()),
	}
	return nil
}

func parseSecurityLevel(s string) (gosnmp.SnmpV3MsgFlags, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "noauthnopriv":
		return gosnmp.NoAuthNoPriv, nil
	case "authnopriv":
		return gosnmp.AuthNoPriv, nil
	case "authpriv":
		return gosnmp.AuthPriv, nil
	}
	return 0, fmt.Errorf("unsupported snmpv3 security level: %q", s)
}

func parseAuthProtocol(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NONE":
		return gosnmp.NoAuth
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	}
	return gosnmp.NoAuth
}

func parsePrivProtocol(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NONE":
		return gosnmp.NoPriv
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	}
	return gosnmp.NoPriv
}

// ReadPoints 批量读取 OID。op=get 精确读单值，op=walk 遍历子树返回多值。
// 单个点位失败不影响其它（标记 quality=bad）。
func ReadPoints(client *gosnmp.GoSNMP, points []Point, logger types.Logger) ([]Data, error) {
	if client == nil {
		return nil, errors.New("snmp client is nil")
	}
	results := make([]Data, 0, len(points))
	failCount := 0
	var lastErr error
	for _, p := range points {
		op := strings.ToLower(strings.TrimSpace(p.Op))
		if op == "walk" {
			ds, err := readWalk(client, p)
			if err != nil {
				results = append(results, Data{Name: p.Name, Address: p.OID, Quality: "bad", Type: "walk", Timestamp: time.Now()})
				failCount++
				lastErr = err
				if logger != nil {
					logger.Errorf("[SNMP] walk %s error: %v", p.OID, err)
				}
			} else {
				results = append(results, ds...)
			}
		} else {
			d, err := readGet(client, p)
			if err != nil {
				d.Quality = "bad"
				failCount++
				lastErr = err
				if logger != nil {
					logger.Errorf("[SNMP] get %s error: %v", p.OID, err)
				}
			}
			results = append(results, d)
		}
	}
	// 全部点位失败：疑似连接级错误，返回 error
	if len(points) > 0 && failCount == len(points) {
		return results, fmt.Errorf("all %d points failed (possible connection error): %w", failCount, lastErr)
	}
	return results, nil
}

// readGet 精确读单个 OID
func readGet(client *gosnmp.GoSNMP, p Point) (Data, error) {
	resp, err := client.Get([]string{p.OID})
	if err != nil {
		return Data{Name: p.Name, Address: p.OID, Timestamp: time.Now()}, err
	}
	if len(resp.Variables) == 0 {
		return Data{Name: p.Name, Address: p.OID, Timestamp: time.Now()}, errors.New("no variable returned")
	}
	return pduToData(p.Name, resp.Variables[0]), nil
}

// readWalk 遍历 OID 子树
func readWalk(client *gosnmp.GoSNMP, p Point) ([]Data, error) {
	out := make([]Data, 0)
	err := client.Walk(p.OID, func(d gosnmp.SnmpPDU) error {
		out = append(out, pduToData(p.Name, d))
		return nil
	})
	if err != nil {
		return out, err
	}
	return out, nil
}

// pduToData 将 gosnmp PDU 转为统一 Data
func pduToData(name string, pdu gosnmp.SnmpPDU) Data {
	return Data{
		Name:      name,
		Address:   pdu.Name,
		Value:     pdu.Value,
		Type:      pduTypeString(pdu.Type),
		Quality:   "good",
		Timestamp: time.Now(),
	}
}

// pduTypeString PDU 类型常量 -> 可读字符串
func pduTypeString(t gosnmp.Asn1BER) string {
	switch t {
	case gosnmp.Integer:
		return "Integer"
	case gosnmp.OctetString:
		return "OctetString"
	case gosnmp.ObjectIdentifier:
		return "ObjectIdentifier"
	case gosnmp.IPAddress:
		return "IPAddress"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.TimeTicks:
		return "TimeTicks"
	case gosnmp.Counter64:
		return "Counter64"
	case gosnmp.Null:
		return "Null"
	}
	return fmt.Sprintf("Asn1BER(%d)", int(t))
}

// WritePoints 批量写入 OID（Set）。任一失败立即返回错误。
func WritePoints(client *gosnmp.GoSNMP, points []Point) error {
	if client == nil {
		return errors.New("snmp client is nil")
	}
	for _, p := range points {
		val, asnType, err := encodeValue(p.Value, p.Type)
		if err != nil {
			return fmt.Errorf("encode %s error: %w", p.OID, err)
		}
		pdus := []gosnmp.SnmpPDU{{Name: p.OID, Type: asnType, Value: val}}
		if _, err := client.Set(pdus); err != nil {
			return fmt.Errorf("set %s error: %w", p.OID, err)
		}
	}
	return nil
}

// encodeValue 按 type 把值的字符串形式解析为 Go 值 + Asn1BER（供 Set）
func encodeValue(value, typ string) (interface{}, gosnmp.Asn1BER, error) {
	v := strings.TrimSpace(value)
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "integer", "int":
		n, err := parseInt(v)
		return n, gosnmp.Integer, err
	case "octetstring", "string":
		return v, gosnmp.OctetString, nil
	case "objectidentifier", "oid":
		return v, gosnmp.ObjectIdentifier, nil
	case "ipaddress", "ip":
		return v, gosnmp.IPAddress, nil
	case "counter32":
		n, err := parseInt(v)
		return n, gosnmp.Counter32, err
	case "gauge32", "uint32":
		n, err := parseInt(v)
		return n, gosnmp.Gauge32, err
	case "timeticks":
		n, err := parseInt(v)
		return n, gosnmp.TimeTicks, err
	case "counter64":
		n, err := parseInt64(v)
		return n, gosnmp.Counter64, err
	}
	return nil, 0, fmt.Errorf("unsupported snmp type: %q", typ)
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
