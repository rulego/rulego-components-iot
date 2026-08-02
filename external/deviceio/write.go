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

package deviceio

import (
	"fmt"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&WriteNode{})
}

// WriteConfig universal acquisition write configuration.
type WriteConfig struct {
	Driver string `json:"driver" label:"Driver" desc:"acquisition driver: modbus, s7, eip, snmp, opcua, mc, fins, dlt645, iec104" required:"true"`
}

// WriteNode universal acquisition write node, delegates to specific protocol write node by driver.
//
// Input (msg.Data): point list JSON [{"name","addr","type","value"}].
type WriteNode struct {
	Config   WriteConfig
	delegate types.Node
}

func (x *WriteNode) New() types.Node { return &WriteNode{} }

func (x *WriteNode) Type() string { return "x/iotWrite" }

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	switch x.Config.Driver {
	case "modbus":
		return x.initDelegate(ruleConfig, configuration, "x/modbusWrite")
	case "s7":
		return x.initDelegate(ruleConfig, configuration, "x/s7Write")
	case "eip":
		return x.initDelegate(ruleConfig, configuration, "x/eipWrite")
	case "snmp":
		return x.initDelegate(ruleConfig, configuration, "x/snmpWrite")
	case "opcua":
		return x.initDelegate(ruleConfig, configuration, "x/opcuaWrite")
	case "mc":
		return x.initDelegate(ruleConfig, configuration, "x/mcWrite")
	case "fins":
		return x.initDelegate(ruleConfig, configuration, "x/finsWrite")
	case "dlt645":
		return x.initDelegate(ruleConfig, configuration, "x/dlt645Write")
	case "iec104":
		return x.initDelegate(ruleConfig, configuration, "x/iec104Write")
	default:
		return fmt.Errorf("unsupported iot write driver: %s", x.Config.Driver)
	}
}

func (x *WriteNode) initDelegate(ruleConfig types.Config, configuration types.Configuration, nodeType string) error {
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

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	if x.delegate != nil {
		x.delegate.OnMsg(ctx, msg)
	}
}

func (x *WriteNode) Destroy() {
	if x.delegate != nil {
		x.delegate.Destroy()
	}
}

func (x *WriteNode) Desc() string {
	return "Universal acquisition write node. Supports modbus, s7, eip, snmp, opcua, mc, fins, dlt645, iec104."
}
