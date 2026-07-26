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

// Package tsdb 提供时序数据库的统一数据模型与驱动接口。
package tsdb

import (
	"context"
	"errors"
)

// ErrUnsupported 表示该 driver 不支持某操作（如只写不查的库收到 Query）。
var ErrUnsupported = errors.New("operation not supported by this tsdb driver")

// SeriesPoint 时序数据点，跨 TSDB 的统一模型。
// 对应 InfluxDB/OpenGemini 的 measurement + tags + fields + timestamp，
// 各 driver 负责将其编码为 line protocol / SQL / 原生协议。
//
// JSON 输入示例：{"measurement":"device1","tags":{"site":"A"},"fields":{"temp":25.3},"timestamp":1721900000000000000}
type SeriesPoint struct {
	Measurement string                 `json:"measurement"` // 测点表/设备表名
	Tags        map[string]string      `json:"tags"`        // 索引维度：deviceId/位置/...
	Fields      map[string]interface{} `json:"fields"`      // 数值/状态值
	Timestamp   int64                  `json:"timestamp"`   // 纳秒时间戳；0 表示由 driver 写入时取当前时间
}

// QueryResult 通用查询结果，按列+行组织。
type QueryResult struct {
	Columns []string
	Rows    []map[string]interface{}
}

// Driver 时序数据库驱动接口。
// db 参数为存储容器标识，各 driver 自行解释：OpenGemini=database、InfluxDB=bucket（构造时绑定，WritePoints 的 db 参数可忽略）、
// TDengine=db、TimescaleDB=schema、PromRemote 不使用。
type Driver interface {
	// WritePoints 批量写入时序点。
	WritePoints(ctx context.Context, db string, points []SeriesPoint) error
	// Query 执行查询；只写库返回 ErrUnsupported。db 语义同 WritePoints（InfluxDB 此处传 org）。
	Query(ctx context.Context, db, sql string) (*QueryResult, error)
	// Close 释放连接。
	Close() error
}
