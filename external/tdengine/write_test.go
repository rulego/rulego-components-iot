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

package tdengine

import (
	"net"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
)

// TestWriteNodeInitTimeout verifies the init validation query does not hang on an unreachable endpoint.
func TestWriteNodeInitTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// accept without responding
			_ = conn
		}
	}()

	old := initQueryTimeout
	initQueryTimeout = 500 * time.Millisecond
	defer func() { initQueryTimeout = old }()

	// Lazy init path: the validation query runs on first GetSafely.
	node := (&WriteNode{}).New().(*WriteNode)
	if err := node.Init(types.Config{}, types.Configuration{
		"dsn": "root:taosdata@http(" + ln.Addr().String() + ")/",
		"db":  "iot_test",
	}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = node.GetSafely()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected init error against blackhole endpoint")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("init blocked too long: %v", elapsed)
	}
}
