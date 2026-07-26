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

// Package tsdbwrite ensures all supported TSDB drivers are registered.
package tsdbwrite

import (
	_ "github.com/rulego/rulego-components-iot/external/influxdb"
	_ "github.com/rulego/rulego-components-iot/external/opengemini"
	_ "github.com/rulego/rulego-components-iot/external/promremote"
	_ "github.com/rulego/rulego-components-iot/external/tdengine"
	_ "github.com/rulego/rulego-components-iot/external/timescaledb"
)
