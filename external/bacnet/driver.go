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

package bacnet

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	bacnetclient "github.com/rulego/rulego-components-iot/pkg/bacnet_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// driver adapts iot_points.Driver to a BACnet client.
type driver struct {
	client   *bacnetclient.Client
	logger   types.Logger
	priority uint8
}

var _ iot_points.Driver = (*driver)(nil)

func newDriver(client *bacnetclient.Client, logger types.Logger, priority uint8) *driver {
	return &driver{client: client, logger: logger, priority: priority}
}

func (d *driver) ReadPoints(points []iot_points.Point) ([]iot_points.Data, error) {
	// Multi-point: one ReadPropertyMultiple request grouped by object, with per-point fallback.
	if len(points) > 1 {
		if data, err := d.readViaRPM(points); err == nil {
			return data, nil
		} else if d.logger != nil {
			d.logger.Warnf("[BACnet] ReadPropertyMultiple failed (%v), falling back to per-point ReadProperty", err)
		}
	}
	return d.readEach(points)
}

// readEach reads points one by one via ReadProperty (single-point and fallback path).
func (d *driver) readEach(points []iot_points.Point) ([]iot_points.Data, error) {
	out := make([]iot_points.Data, 0, len(points))
	failCount := 0
	var lastErr error
	now := time.Now().UnixNano()
	for _, p := range points {
		a, err := ParsePointAddr(p.Addr)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			failCount++
			lastErr = err
			continue
		}
		val, err := d.client.ReadProperty(a.ObjectType, a.Instance, a.Property)
		if err != nil {
			out = append(out, iot_points.Data{Name: p.Name, Error: err.Error()})
			failCount++
			lastErr = err
			if d.logger != nil {
				d.logger.Errorf("[BACnet] read %s: %v", p.Addr, err)
			}
			continue
		}
		out = append(out, iot_points.Data{Name: p.Name, Value: iot_points.ScaleValue(val, p), Timestamp: now})
	}
	if len(points) > 0 && failCount == len(points) {
		return out, fmt.Errorf("all %d bacnet points failed: %w", failCount, lastErr)
	}
	return out, nil
}

// readViaRPM reads all points in one ReadPropertyMultiple request, grouped by object.
// Returns an error if RPM cannot be used (the caller falls back to readEach).
func (d *driver) readViaRPM(points []iot_points.Point) ([]iot_points.Data, error) {
	addrs := make([]PointAddr, len(points))
	for i, p := range points {
		a, err := ParsePointAddr(p.Addr)
		if err != nil {
			return nil, err
		}
		addrs[i] = a
	}
	// Group by (objectType, instance), preserving first-seen order.
	type group struct {
		objType  uint16
		instance uint32
		propSet  map[uint32]struct{}
	}
	order := make([]string, 0)
	groups := make(map[string]*group)
	for _, a := range addrs {
		key := fmt.Sprintf("%d:%d", a.ObjectType, a.Instance)
		g, ok := groups[key]
		if !ok {
			g = &group{objType: a.ObjectType, instance: a.Instance, propSet: make(map[uint32]struct{})}
			groups[key] = g
			order = append(order, key)
		}
		g.propSet[a.Property] = struct{}{}
	}
	specs := make([]bacnetclient.AccessSpec, 0, len(order))
	for _, k := range order {
		g := groups[k]
		props := make([]uint32, 0, len(g.propSet))
		for p := range g.propSet {
			props = append(props, p)
		}
		specs = append(specs, bacnetclient.AccessSpec{ObjectType: g.objType, Instance: g.instance, Properties: props})
	}
	results, err := d.client.ReadPropertyMultiple(specs)
	if err != nil {
		return nil, err
	}
	resIndex := make(map[string]bacnetclient.ReadAccessResult, len(results))
	for _, r := range results {
		resIndex[fmt.Sprintf("%d:%d", r.ObjectType, r.Instance)] = r
	}
	out := make([]iot_points.Data, 0, len(points))
	now := time.Now().UnixNano()
	for i, p := range points {
		a := addrs[i]
		r, ok := resIndex[fmt.Sprintf("%d:%d", a.ObjectType, a.Instance)]
		if !ok {
			out = append(out, iot_points.Data{Name: p.Name, Error: "no result for object"})
			continue
		}
		if e, hasErr := r.Errors[a.Property]; hasErr {
			out = append(out, iot_points.Data{Name: p.Name, Error: e.Error()})
			continue
		}
		v, ok := r.Values[a.Property]
		if !ok {
			out = append(out, iot_points.Data{Name: p.Name, Error: "no value for property"})
			continue
		}
		out = append(out, iot_points.Data{Name: p.Name, Value: iot_points.ScaleValue(v, p), Timestamp: now})
	}
	return out, nil
}

func (d *driver) WritePoints(points []iot_points.Point) error {
	for _, p := range points {
		a, err := ParsePointAddr(p.Addr)
		if err != nil {
			return fmt.Errorf("bacnet addr %s: %w", p.Addr, err)
		}
		tag, val, err := encodeValue(p.Type, p.Value)
		if err != nil {
			return fmt.Errorf("bacnet encode %s: %w", p.Name, err)
		}
		if err := d.client.WriteProperty(a.ObjectType, a.Instance, a.Property, tag, val, d.priority); err != nil {
			return fmt.Errorf("bacnet write %s: %w", p.Name, err)
		}
	}
	return nil
}

// encodeValue parses a value string by point type into a BACnet application tag and Go value.
// Empty type defaults to real (analog objects); multi-state uses ENUMERATED.
func encodeValue(typeStr, valueStr string) (uint8, interface{}, error) {
	switch strings.ToUpper(strings.TrimSpace(typeStr)) {
	case "", "FLOAT32", "REAL":
		f, err := strconv.ParseFloat(valueStr, 64)
		return bacnetclient.AppTagReal, f, err
	case "FLOAT64", "DOUBLE":
		f, err := strconv.ParseFloat(valueStr, 64)
		return bacnetclient.AppTagDouble, f, err
	case "BOOL", "BOOLEAN":
		b, err := parseBool(valueStr)
		return bacnetclient.AppTagBoolean, b, err
	case "STRING":
		return bacnetclient.AppTagCharacterString, valueStr, nil
	case "ENUMERATED", "ENUM":
		n, err := strconv.ParseUint(valueStr, 10, 32)
		return bacnetclient.AppTagEnumerated, n, err
	case "UINT16", "UINT32", "UINT64", "UINT":
		n, err := strconv.ParseUint(valueStr, 10, 64)
		return bacnetclient.AppTagUnsignedInt, n, err
	case "INT16", "INT32", "INT64", "INT":
		n, err := strconv.ParseInt(valueStr, 10, 64)
		return bacnetclient.AppTagSignedInt, n, err
	}
	// Unknown type: best effort as real.
	f, err := strconv.ParseFloat(valueStr, 64)
	return bacnetclient.AppTagReal, f, err
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "on":
		return true, nil
	case "false", "0", "off", "":
		return false, nil
	}
	return false, fmt.Errorf("invalid bool %q", s)
}
