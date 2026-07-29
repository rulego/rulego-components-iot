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

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseServer 解析 "host" 或 "host:port" 格式地址，返回 host 与端口。
// 缺省端口时用 defaultPort；空地址或非法端口（非数字/越界）返回 error。
func ParseServer(server string, defaultPort int) (string, int, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", 0, errors.New("empty server address")
	}
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return server, defaultPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in server %q", server)
	}
	return host, port, nil
}
