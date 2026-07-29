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

// Package tsdb provides universal time-series database write (x/tsdbWrite)
// and query (x/tsdbQuery) nodes, supporting multiple TSDB backends through a unified configuration.
package tsdb

import (
	"fmt"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&Node{})
}

// Config defines the universal TSDB write configuration.
type Config struct {
	Driver string `json:"driver" label:"Driver" desc:"TSDB driver: opengemini, influxdb, tdengine, promremote, timescaledb" required:"true"`
	// 采集数据映射（可选）。配置 Measurement 后，输入按采集点数组透视为 SeriesPoint；
	// 不配置则输入须为 SeriesPoint 格式（原样透传）。
	tsdb.AcquisitionMapping `json:",squash"`
}

// Node delegates writes to a concrete TSDB write node selected by driver.
//
// 输入(msg.Data)：
//   - 未配置 measurement：SeriesPoint JSON 数组/单对象（见 pkg/tsdb.SeriesPoint），非 JSON 按 line protocol 解析。
//   - 配置了 measurement：采集点数组 [{"name","value","timestamp","error"}]，内部透视为单个 SeriesPoint
//     （measurement=配置值，fields=各点 name→value，tags=配置模板渲染，timestamp=各点最大时间戳）。
type Node struct {
	Config Config
	// delegate holds the concrete write node selected at init time.
	delegate types.Node
}

// New creates a new universal TSDB write node.
func (x *Node) New() types.Node {
	return &Node{}
}

// Type returns the component type.
func (x *Node) Type() string {
	return "x/tsdbWrite"
}

// Init initializes the delegate write node according to the configured driver.
func (x *Node) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	switch x.Config.Driver {
	case "opengemini":
		return x.initDelegate(ruleConfig, configuration, "x/opengeminiWrite")
	case "influxdb":
		return x.initDelegate(ruleConfig, configuration, "x/influxdbWrite")
	case "tdengine":
		return x.initDelegate(ruleConfig, configuration, "x/tdengineWrite")
	case "promremote":
		return x.initDelegate(ruleConfig, configuration, "x/promremoteWrite")
	case "timescaledb":
		return x.initDelegate(ruleConfig, configuration, "x/timescaledbWrite")
	default:
		return fmt.Errorf("unsupported tsdb driver: %s", x.Config.Driver)
	}
}

// initDelegate creates and initializes the concrete write node from the registry.
func (x *Node) initDelegate(ruleConfig types.Config, configuration types.Configuration, nodeType string) error {
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

// OnMsg forwards the message to the selected delegate node,
// mapping acquisition points to SeriesPoint when Measurement is configured.
func (x *Node) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	if x.delegate == nil {
		return
	}
	if x.Config.Enabled() {
		env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
		if mapped, ok := x.Config.MapData(msg.GetData(), env); ok {
			msg.SetDataType(types.JSON)
			msg.SetData(mapped)
		}
		// 映射不适用（输入非点数组）则原样透传，交由 delegate 处理
	}
	x.delegate.OnMsg(ctx, msg)
}

// Destroy releases resources owned by the delegate node.
func (x *Node) Destroy() {
	if x.delegate != nil {
		x.delegate.Destroy()
	}
}

// Desc returns the component description.
func (x *Node) Desc() string {
	return "Universal time-series database write node. Supports OpenGemini, InfluxDB, TDengine, PromRemote, and TimescaleDB."
}
