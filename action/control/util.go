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

// Package control 提供软 PLC 式逻辑控制节点(协议无关,纯消息处理):
// 定时(timer,TON/TOF)与看门狗(watchdog,失联→故障安全)。判断/计数/时序/模式等
// 能力请复用 streamsql、expr、cache、endpoint/schedule;本包只补"需要定时自发"的元件。
package control

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// genKey 内部元数据键:闹钟消息携带的触发代次(沿用 _ 前缀内部键惯例)。
const genKey = "_ctrlGen"

// parseDurationMs 把时长串(如 3s/500ms)解析为毫秒。
func parseDurationMs(s string) (int64, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return d.Milliseconds(), nil
}

// toBool 把字符串解释为布尔:true/1/非零数字 为 true;空/false/0/null 为 false。
func toBool(s string) bool {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "true", "1":
		return true
	case "", "false", "0", "null":
		return false
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f != 0
	}
	return false
}
