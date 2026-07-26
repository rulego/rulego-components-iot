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

package tsdb

import (
	"encoding/json"
	"fmt"
	"strings"

	lineprotocol "github.com/influxdata/line-protocol"
)

// ParsePoints parses input data into a SeriesPoint list.
// When isJSON is true, data is parsed as a JSON SeriesPoint array or single object;
// otherwise it is parsed as line protocol text (measurement,tag=v field=v timestamp).
func ParsePoints(data string, isJSON bool) ([]SeriesPoint, error) {
	if isJSON {
		var points []SeriesPoint
		if err := json.Unmarshal([]byte(data), &points); err != nil {
			var single SeriesPoint
			if err := json.Unmarshal([]byte(data), &single); err != nil {
				return nil, err
			}
			points = append(points, single)
		}
		if len(points) == 0 {
			return nil, fmt.Errorf("no points in msg.Data")
		}
		return points, nil
	}
	return ParseLineProtocol(data)
}

// ParseLine parses a single line of line protocol into a SeriesPoint.
func ParseLine(line string) (*SeriesPoint, error) {
	points, err := ParseLineProtocol(line)
	if err != nil {
		return nil, err
	}
	if len(points) == 0 {
		return nil, fmt.Errorf("invalid line format")
	}
	return &points[0], nil
}

// ParseLineProtocol parses line protocol text into a SeriesPoint list.
func ParseLineProtocol(data string) ([]SeriesPoint, error) {
	// StreamParser 按行产出记录，补尾随换行确保最后一行被解析。
	parser := lineprotocol.NewStreamParser(strings.NewReader(data + "\n"))
	var points []SeriesPoint
	for {
		m, err := parser.Next()
		if err == lineprotocol.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		p := SeriesPoint{
			Measurement: m.Name(),
			Tags:        make(map[string]string, len(m.TagList())),
			Fields:      make(map[string]interface{}, len(m.FieldList())),
			Timestamp:   m.Time().UnixNano(),
		}
		for _, tag := range m.TagList() {
			p.Tags[tag.Key] = tag.Value
		}
		for _, field := range m.FieldList() {
			p.Fields[field.Key] = field.Value
		}
		points = append(points, p)
	}
	return points, nil
}
