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

package tsdb

import (
	"fmt"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&QueryNode{})
}

// QueryConfig defines the universal TSDB query configuration.
// Connection and query fields (server/database, url/bucket/org/token, dsn/db, command/query) are parsed by the selected driver's query node.
type QueryConfig struct {
	Driver string `json:"driver" label:"Driver" desc:"TSDB driver: opengemini, influxdb, tdengine, timescaledb" required:"true"`
}

// QueryNode delegates queries to a concrete TSDB query node selected by driver.
// Query results unified as tsdb.QueryResult (Columns+Rows) JSON written to msg.Data, routed via Success/Failure.
type QueryNode struct {
	Config QueryConfig
	// delegate holds the concrete query node selected at init time.
	delegate types.Node
}

// New creates a new universal TSDB query node.
func (x *QueryNode) New() types.Node {
	return &QueryNode{}
}

// Type returns the component type.
func (x *QueryNode) Type() string {
	return "x/tsdbQuery"
}

// Init initializes the delegate query node according to the configured driver.
func (x *QueryNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	switch x.Config.Driver {
	case "opengemini":
		return x.initDelegate(ruleConfig, configuration, "x/opengeminiQuery")
	case "influxdb":
		return x.initDelegate(ruleConfig, configuration, "x/influxdbQuery")
	case "tdengine":
		return x.initDelegate(ruleConfig, configuration, "x/tdengineQuery")
	case "timescaledb":
		return x.initDelegate(ruleConfig, configuration, "x/timescaledbQuery")
	default:
		return fmt.Errorf("unsupported tsdb driver: %s", x.Config.Driver)
	}
}

// initDelegate creates and initializes the concrete query node from the registry.
func (x *QueryNode) initDelegate(ruleConfig types.Config, configuration types.Configuration, nodeType string) error {
	node, err := rulego.Registry.NewNode(nodeType)
	if err != nil {
		return err
	}
	if err := node.Init(ruleConfig, configuration); err != nil {
		return err
	}
	x.delegate = node
	return nil
}

// OnMsg forwards the message to the selected delegate node.
func (x *QueryNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	if x.delegate == nil {
		return
	}
	x.delegate.OnMsg(ctx, msg)
}

// Destroy releases resources owned by the delegate node.
func (x *QueryNode) Destroy() {
	if x.delegate != nil {
		x.delegate.Destroy()
	}
}

// Desc returns the component description.
func (x *QueryNode) Desc() string {
	return "Universal time-series database query node. Supports OpenGemini, InfluxDB, TDengine, and TimescaleDB."
}
