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

// Package deviceio provides universal device I/O facade nodes (x/iotRead and x/iotWrite),
// delegating to concrete protocol nodes through a unified driver configuration.
package deviceio

import (
	"fmt"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&Node{})
}

// Config defines the universal acquisition read configuration.
type Config struct {
	Driver string `json:"driver" label:"Driver" desc:"acquisition driver: modbus, s7, eip, snmp, opcua, mc, fins, dlt645, iec104" required:"true"`
}

// Node delegates reads to a concrete acquisition read node selected by driver.
type Node struct {
	Config   Config
	delegate types.Node
}

func (x *Node) New() types.Node { return &Node{} }

func (x *Node) Type() string { return "x/iotRead" }

func (x *Node) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	switch x.Config.Driver {
	case "modbus":
		return x.initDelegate(ruleConfig, configuration, "x/modbusRead")
	case "s7":
		return x.initDelegate(ruleConfig, configuration, "x/s7Read")
	case "eip":
		return x.initDelegate(ruleConfig, configuration, "x/eipRead")
	case "snmp":
		return x.initDelegate(ruleConfig, configuration, "x/snmpRead")
	case "opcua":
		return x.initDelegate(ruleConfig, configuration, "x/opcuaRead")
	case "mc":
		return x.initDelegate(ruleConfig, configuration, "x/mcRead")
	case "fins":
		return x.initDelegate(ruleConfig, configuration, "x/finsRead")
	case "dlt645":
		return x.initDelegate(ruleConfig, configuration, "x/dlt645Read")
	case "iec104":
		return x.initDelegate(ruleConfig, configuration, "x/iec104Read")
	default:
		return fmt.Errorf("unsupported iot read driver: %s", x.Config.Driver)
	}
}

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

func (x *Node) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	if x.delegate != nil {
		x.delegate.OnMsg(ctx, msg)
	}
}

func (x *Node) Destroy() {
	if x.delegate != nil {
		x.delegate.Destroy()
	}
}

func (x *Node) Desc() string {
	return "Universal acquisition read node. Supports modbus, s7, eip, snmp, opcua, mc, fins, dlt645, iec104."
}
