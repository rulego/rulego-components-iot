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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseServer host:port parsing, default port and invalid input
func TestParseServer(t *testing.T) {
	host, port, err := ParseServer("192.168.1.10:6001", 6000)
	assert.Nil(t, err)
	assert.Equal(t, "192.168.1.10", host)
	assert.Equal(t, 6001, port)

	// host only: fill default port
	host, port, err = ParseServer(" 192.168.1.10 ", 6000)
	assert.Nil(t, err)
	assert.Equal(t, "192.168.1.10", host)
	assert.Equal(t, 6000, port)

	// Empty address, non-numeric port, out-of-range port all error
	_, _, err = ParseServer("", 6000)
	assert.NotNil(t, err)
	_, _, err = ParseServer("host:abc", 6000)
	assert.NotNil(t, err)
	_, _, err = ParseServer("host:99999", 6000)
	assert.NotNil(t, err)
	_, _, err = ParseServer("host:-1", 6000)
	assert.NotNil(t, err)
}
