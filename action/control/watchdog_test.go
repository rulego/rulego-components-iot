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

package control

// Watchdog timing behavior (passthrough, disconnect trigger, re-arm) covered by e2e_test.go via real rule engine;
// Here only test basic behavior that does not depend on engine.

import (
	"testing"

	"github.com/rulego/rulego/api/types"
	"github.com/stretchr/testify/assert"
)

func TestWatchdogBasics(t *testing.T) {
	n := (&WatchdogNode{}).New()
	assert.Equal(t, "x/control/watchdog", n.Type())
	assert.Equal(t, "10s", n.(*WatchdogNode).Config.Timeout)
}

func TestWatchdogInit(t *testing.T) {
	n := (&WatchdogNode{}).New()
// Missing failsafe -> error
	err := n.Init(types.NewConfig(), types.Configuration{"timeout": "1s"})
	assert.NotNil(t, err)

// Static timeout pre-parsed
	err = n.Init(types.NewConfig(), types.Configuration{"timeout": "2s", "failsafe": "{}"})
	assert.Nil(t, err)
	assert.Equal(t, int64(2000), n.(*WatchdogNode).staticTimeoutMs)

// Template timeout -> -1 (render each time)
	err = n.Init(types.NewConfig(), types.Configuration{"timeout": "${metadata.to}", "failsafe": "{}"})
	assert.Nil(t, err)
	assert.Equal(t, int64(-1), n.(*WatchdogNode).staticTimeoutMs)
}
