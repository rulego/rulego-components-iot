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

// Package control provides soft-PLC style logic control nodes (protocol agnostic, pure message processing):
// Timer (timer,TON/TOF) and watchdog (watchdog, disconnect->failsafe). Judgment/count/timing/pattern etc.
// Capabilities please reuse streamsql, expr, cache, endpoint/schedule; this package only supplements components that "require spontaneous timing".
package control

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// genKey internal metadata key: trigger generation carried by alarm message (following _ prefix internal key convention).
const genKey = "_ctrlGen"

// parseDurationMs parses duration string (e.g. 3s/500ms) to milliseconds.
func parseDurationMs(s string) (int64, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return d.Milliseconds(), nil
}

// toBool interprets string as boolean: true/1/non-zero number is true; empty/false/0/null is false.
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
