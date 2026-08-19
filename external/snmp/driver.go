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

// driver adapts iot_points.Driver to SNMP client.
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
	return buildReadDatas(datas, points, cp), nil
}

// buildReadDatas maps client results to unified Data. A walk result appends its
// actual OID to Name when it differs from the configured OID; every value of a
// walk subtree passes the point's scale/offset conversion.
func buildReadDatas(datas []snmpclient.Data, points []iot_points.Point, cp []snmpclient.Point) []iot_points.Data {
	oidByName := make(map[string]string, len(cp))
	for _, c := range cp {
		oidByName[c.Name] = c.OID
	}
	pointByName := make(map[string]iot_points.Point, len(points))
	for _, p := range points {
		pointByName[p.Name] = p
	}
	out := make([]iot_points.Data, 0, len(datas))
	for _, dd := range datas {
		if dd.Quality == "bad" {
			out = append(out, iot_points.Data{Name: dd.Name, Error: "read failed (quality=bad)"})
			continue
		}
		name := dd.Name
		// actual OID (leading dot removed) appends to point name when differs from config
		if actual := strings.TrimPrefix(dd.Address, "."); actual != "" && actual != oidByName[dd.Name] {
			name = dd.Name + "." + actual
		}
		out = append(out, iot_points.Data{
			Name:      name,
			Value:     iot_points.ScaleValue(dd.Value, pointByName[dd.Name]),
			Timestamp: dd.Timestamp.UnixNano(),
		})
	}
	return out
}

func (d *driver) WritePoints(points []iot_points.Point) error {
	cp := make([]snmpclient.Point, 0, len(points))
	for _, p := range points {
		cp = append(cp, toSnmpClientPoint(p))
	}
	return snmpclient.WritePoints(d.client, cp)
}

// toSnmpClientPoint maps unified Point (Addr=OID) to snmpclient.Point.
// Read defaults to get; Addr with "walk:" prefix uses walk (prefix stripped as OID).
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
