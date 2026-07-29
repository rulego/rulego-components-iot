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

package eip

import (
	"strings"

	"github.com/danomagnum/gologix"
	eipclient "github.com/rulego/rulego-components-iot/pkg/eip_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// driver 适配 iot_points.Driver 到 EtherNet/IP client。
type driver struct {
	client *gologix.Client
	logger types.Logger
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *gologix.Client, logger types.Logger) *driver {
	return &driver{client: client, logger: logger}
}

func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	cp := make([]eipclient.Point, 0, len(points))
	for _, p := range points {
		cp = append(cp, toEipClientPoint(p))
	}
	datas, err := eipclient.ReadPoints(d.client, cp, d.logger)
	if err != nil {
		return nil, err
	}
	out := make([]iot_points.Data, 0, len(datas))
	for i, dd := range datas {
		var p iot_points.Point
		if i < len(points) {
			p = points[i]
		}
		out = append(out, iot_points.NewData(dd.Name, dd.Value, dd.Quality == "bad", dd.Timestamp, p))
	}
	return out, nil
}

func (d *driver) WritePoints(points []iot_points.Point) error {
	cp := make([]eipclient.Point, 0, len(points))
	for _, p := range points {
		cp = append(cp, toEipClientPoint(p))
	}
	return eipclient.WritePoints(d.client, cp)
}

// toEipClientPoint 把统一 Point（Addr=tag 名）映射为 eipclient.Point。
func toEipClientPoint(p iot_points.Point) eipclient.Point {
	return eipclient.Point{
		Name:  p.Name,
		Tag:   p.Addr,
		Type:  mapType(p.Type),
		Value: p.Value,
	}
}

// mapType 统一类型枚举 -> EIP 原生类型；未知类型透传。
func mapType(t string) string {
	switch strings.ToUpper(t) {
	case iot_points.TypeBool:
		return "BOOL"
	case iot_points.TypeInt16:
		return "INT"
	case iot_points.TypeInt32:
		return "DINT"
	case iot_points.TypeFloat32:
		return "REAL"
	case iot_points.TypeString:
		return "STRING"
	default:
		return t
	}
}
