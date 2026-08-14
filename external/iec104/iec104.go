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

// Package iec104 provides IEC 60870-5-104 power telecontrol protocol master (control station) read nodes,
// for collecting substation (controlled station) telemetry/remote signaling/pulse from power dispatch/grid/substation monitoring.
//
// Usage:
//   - Scheduled collection: use endpoint/schedule, configure points below (addr=Information Object Address IOA).
//   - On-demand read: msg.Data points take precedence (dynamic scenarios).
//
// Collection model: read initiates general interrogation (GI), substation uploads all data then values fetched by IOA.
// Point fields support ${msg.xx} / ${metadata.xx} template variables.
package iec104

import (
	"errors"
	"sync"

	"github.com/rulego/rulego"
	iec104client "github.com/rulego/rulego-components-iot/pkg/iec104_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// Register nodes
// iec104OpLocks serializes concurrent interrogation on a shared client: concurrent
// GI rounds clear each other's completion flags and stall to timeout.
var iec104OpLocks iot_points.OpLocks

// closeClient closes the IEC 104 client.
func closeClient(client *iec104client.Client) error {
	if client != nil {
		return client.Close()
	}
	return nil
}

func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// iec104StatusSetter forwards cs104 link state to a SharedNode.
type iec104StatusSetter interface {
	SetStatus(types.NodeStatus, string)
}

// newIEC104Client builds a client and wires cs104 link callbacks to the SharedNode status.
func newIEC104Client(cfg iec104client.ConfigProp, setter iec104StatusSetter) (*iec104client.Client, error) {
	h := iec104client.DefaultHolder(cfg)
	h.OnLink = func(active bool) {
		if active {
			setter.SetStatus(types.StatusConnected, "")
		} else {
			setter.SetStatus(types.StatusReconnecting, "")
		}
	}
	return h.NewClient()
}

// Configuration connection configuration
type Configuration struct {
	// Substation address, format host:port, IEC 104 default port 2404
	Server string `json:"server" label:"Server" desc:"host:port, default port 2404" required:"true" ref:"primary"`
	// Common address (CA/station address), default 1
	CommonAddr int `json:"commonAddr" label:"CommonAddr" desc:"common address of ASDU, default 1"`
	// General interrogation wait timeout in seconds, default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"interrogation wait timeout in seconds, default 5"`
	// Default points table (addr=IOA). Used by scheduled collection (schedule trigger); msg.Data points take precedence
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table (addr=IOA); msg.Data points take precedence"`
}

// GetServer implements iec104client.ConfigProp
func (c Configuration) GetServer() string { return c.Server }

// GetCommonAddr implements iec104client.ConfigProp
func (c Configuration) GetCommonAddr() int { return c.CommonAddr }

// GetTimeout implements iec104client.ConfigProp
func (c Configuration) GetTimeout() int { return c.Timeout }

// ------------------------------------------------------------------------------------------------
// ReadNode IEC 104 read node
// ------------------------------------------------------------------------------------------------

// ReadNode initiates general interrogation to batch collect substation points, results (unified Data list) written to msg.Data, routed via Success link.
//
// Input (msg.Data optional): point list JSON, same format as points config. Empty uses configured points.
// Output (msg.Data): [{"name","value","timestamp","error"}] (timestamp in ns; error present only on single-point failure)
type ReadNode struct {
	base.SharedNode[*iec104client.Client]
	Config Configuration
	// reconnectLocker protects reconnection
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/iec104Read"
}

// New default configuration
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:     "127.0.0.1:2404",
			CommonAddr: 1,
			Timeout:    5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "100", Type: "M_SP_NA_1"},
			},
		},
	}
}

// Init initializes
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	// Enable same-chain connection pool: local connections registered to chain directory by node ID, for chain-internal ref:// borrowing
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Retry/reconnect handled by the shared runner; reads are
// serialized so concurrent GI rounds cannot clear each other's completion flags.
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no iec104 points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunRead(ctx, msg, func(client *iec104client.Client) ([]iot_points.Data, error) {
		return newDriver(client).ReadPoints(rendered)
	}, x.runOpts())
}

func (x *ReadNode) runOpts() iot_points.RunOpts[*iec104client.Client] {
	return iot_points.RunOpts[*iec104client.Client]{
		Shared:         &x.SharedNode,
		Reconnect:      x.ReconnectNode,
		OpLocks:        &iec104OpLocks,
		Logger:         x.RuleConfig.Logger,
		Prefix:         "[IEC104]",
		RetryOnTimeout: true,
	}
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *ReadNode) ReconnectNode(old *iec104client.Client, attempt int) (*iec104client.Client, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "iec104", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *ReadNode) newClient() (*iec104client.Client, error) {
	return newIEC104Client(x.Config, &x.SharedNode)
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // only owner cleans up operation lock
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			iec104OpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *ReadNode) Desc() string {
	return "IEC 60870-5-104 master for reading substation points via interrogation. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode IEC 104 write node (remote control/remote adjustment)
// ------------------------------------------------------------------------------------------------

// WriteNode sends control commands (single/double) or setpoint commands to substation.
//
// Input (msg.Data): point list JSON [{"name","addr","type","value"}],
//   - addr=IOA (Information Object Address)
//   - type=command type: C_SC_NA_1(single) / C_DC_NA_1(double) / C_SE_NB_1(scaled setpoint) / C_SE_NC_1(float setpoint)
//   - value: single command true/false; double command 1(close)/2(open); setpoint is numeric value
type WriteNode struct {
	base.SharedNode[*iec104client.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *WriteNode) Type() string {
	return "x/iec104Write"
}

// New default configuration
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:     "127.0.0.1:2404",
			CommonAddr: 1,
			Timeout:    5,
		},
	}
}

// Init initializes
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Retry/reconnect handled by the shared runner.
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no iec104 write points: pass [{\"addr\",\"type\",\"value\"}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunWrite(ctx, msg, func(client *iec104client.Client) error {
		return newDriver(client).WritePoints(rendered)
	}, x.runOpts())
}

func (x *WriteNode) runOpts() iot_points.RunOpts[*iec104client.Client] {
	return iot_points.RunOpts[*iec104client.Client]{
		Shared:         &x.SharedNode,
		Reconnect:      x.ReconnectNode,
		OpLocks:        &iec104OpLocks,
		Logger:         x.RuleConfig.Logger,
		Prefix:         "[IEC104]",
		RetryOnTimeout: true,
	}
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *WriteNode) ReconnectNode(old *iec104client.Client, attempt int) (*iec104client.Client, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "iec104", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *WriteNode) newClient() (*iec104client.Client, error) {
	return newIEC104Client(x.Config, &x.SharedNode)
}

// Destroy cleans up resources
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // only owner cleans up operation lock
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			iec104OpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *WriteNode) Desc() string {
	return "IEC 60870-5-104 master for control commands (single/double/setpoint). Routes to Success/Failure"
}

// renderPoints renders ${msg.xx}/${metadata.xx} templates in point fields.
func renderPoints(ctx types.RuleContext, msg types.RuleMsg, pts []iot_points.Point) []iot_points.Point {
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rendered := make([]iot_points.Point, len(pts))
	for i := range pts {
		rendered[i] = iot_points.RenderPoint(pts[i], env)
	}
	return rendered
}
