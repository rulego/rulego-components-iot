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

package snmp

import (
	"strings"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	snmpclient "github.com/rulego/rulego-components-iot/pkg/snmp_client"
	"github.com/rulego/rulego/api/types"
)

// driver 适配 iot_points.Driver 到 SNMP client。
type driver struct {
	client *gosnmp.GoSNMP
	logger types.Logger
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *gosnmp.GoSNMP, logger types.Logger) *driver {
	return &driver{client: client, logger: logger}
}

func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	cp := make([]snmpclient.Point, 0, len(points))
	for _, p := range points {
		cp = append(cp, toSnmpClientPoint(p))
	}
	datas, err := snmpclient.ReadPoints(d.client, cp, d.logger)
	if err != nil {
		return nil, err
	}
	// 点名 -> 配置 OID：walk 结果的实际 OID 与配置不同时并入 Name
	oidByName := make(map[string]string, len(cp))
	for _, c := range cp {
		oidByName[c.Name] = c.OID
	}
	out := make([]iot_points.Data, 0, len(datas))
	for _, dd := range datas {
		if dd.Quality == "bad" {
			out = append(out, iot_points.Data{Name: dd.Name, Error: "read failed (quality=bad)"})
			continue
		}
		name := dd.Name
		// 实际 OID（去前导点）与配置不同时，点名并入 OID 后缀
		if dd.Address != "" && strings.TrimPrefix(dd.Address, ".") != oidByName[dd.Name] {
			name = dd.Name + "." + dd.Address
		}
		out = append(out, iot_points.Data{
			Name:      name,
			Value:     dd.Value,
			Timestamp: dd.Timestamp.UnixNano(),
		})
	}
	return out, nil
}

func (d *driver) WritePoints(points []iot_points.Point) error {
	cp := make([]snmpclient.Point, 0, len(points))
	for _, p := range points {
		cp = append(cp, toSnmpClientPoint(p))
	}
	return snmpclient.WritePoints(d.client, cp)
}

// toSnmpClientPoint 把统一 Point（Addr=OID）映射为 snmpclient.Point。
// 读操作默认 get；Addr 以 "walk:" 前缀时走 walk（前缀剥离后为 OID）。
func toSnmpClientPoint(p iot_points.Point) snmpclient.Point {
	op, oid := "get", p.Addr
	if strings.HasPrefix(strings.ToUpper(p.Addr), "WALK:") {
		op, oid = "walk", strings.TrimSpace(p.Addr[5:])
	}
	return snmpclient.Point{
		Name:  p.Name,
		OID:   oid,
		Op:    op,
		Type:  p.Type,
		Value: p.Value,
	}
}
