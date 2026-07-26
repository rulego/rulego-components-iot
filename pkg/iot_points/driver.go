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

package iot_points

// Driver 采集驱动接口。driver 持有协议连接（由 SharedNode 管理生命周期），
// 负责解析 Point.Addr 为协议寻址并读写设备。
type Driver interface {
	// ReadPoints 读取点位，返回每个点位的采集结果。
	ReadPoints(points []Point) ([]Data, error)
	// WritePoints 写入点位（Value 字段为写入值）。
	WritePoints(points []Point) error
}
