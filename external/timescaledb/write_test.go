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

package timescaledb

import (
	"testing"
	"time"
)

// TestWithConnectTimeout verifies DSN augmentation with pq's dial timeout.
func TestWithConnectTimeout(t *testing.T) {
	cases := []struct {
		dsn  string
		want string
	}{
		{
			"host=localhost port=5432 user=postgres dbname=ts sslmode=disable",
			"host=localhost port=5432 user=postgres dbname=ts sslmode=disable connect_timeout=10",
		},
		{
			"postgres://user:pass@localhost:5432/ts",
			"postgres://user:pass@localhost:5432/ts?connect_timeout=10",
		},
		{
			"postgres://user:pass@localhost:5432/ts?sslmode=disable",
			"postgres://user:pass@localhost:5432/ts?sslmode=disable&connect_timeout=10",
		},
		// existing connect_timeout is preserved untouched
		{
			"host=localhost connect_timeout=3",
			"host=localhost connect_timeout=3",
		},
	}
	for _, c := range cases {
		if got := withConnectTimeout(c.dsn, 10*time.Second); got != c.want {
			t.Fatalf("withConnectTimeout(%q) = %q, want %q", c.dsn, got, c.want)
		}
	}
}
