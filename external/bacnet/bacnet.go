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

// Package bacnet provides BACnet/IP read (ReadNode) and write (WriteNode) nodes for building
// automation devices (HVAC controllers, sensors, VAV boxes, etc.).
//
// Usage:
//   - Scheduled collection: use endpoint/schedule upstream, configure points (addr: <objectType>:<instance>[:<property>]).
//   - On-demand read/write: msg.Data with point list takes priority (dynamic scenarios).
//
// All point fields support ${msg.xx} / ${metadata.xx} template variables.
package bacnet

import (
	"errors"
	"sync"
	"time"

	"github.com/rulego/rulego"
	bacnetclient "github.com/rulego/rulego-components-iot/pkg/bacnet_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// Configuration connection config shared by read/write nodes.
type Configuration struct {
	// Device address host or host:port, default port 47808
	Server string `json:"server" label:"Server" desc:"host or host:port, default port 47808" required:"true" ref:"primary"`
	// Request timeout (seconds), default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// Write priority 1-16 (0 = omit, use device default)
	Priority uint8 `json:"priority" label:"Priority" desc:"write priority 1-16, 0=omit"`
	// Default points table. Used for scheduled collection; msg.Data points take precedence.
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

func (c Configuration) GetServer() string { return c.Server }
func (c Configuration) GetTimeout() int   { return c.Timeout }

func closeClient(c *bacnetclient.Client) error {
	if c != nil {
		return c.Close()
	}
	return nil
}

func newClient(c Configuration) (*bacnetclient.Client, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	return bacnetclient.NewClient(c.Server, time.Duration(timeout)*time.Second)
}

// bacnetOpLocks serializes concurrent read/write on a shared client connection.
var bacnetOpLocks iot_points.OpLocks

// ------------------------------------------------------------------------------------------------
// ReadNode BACnet read node
// ------------------------------------------------------------------------------------------------

// ReadNode batch reads BACnet object properties, writes results (unified Data list) to msg.Data, routes via Success.
type ReadNode struct {
	base.SharedNode[*bacnetclient.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

func (x *ReadNode) Type() string { return "x/bacnetRead" }

func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:47808",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "supplyTemp", Addr: "analog-input:0"},
			},
		},
	}
}

func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no bacnet points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunRead(ctx, msg, func(client *bacnetclient.Client) ([]iot_points.Data, error) {
		return newDriver(client, x.RuleConfig.Logger, x.Config.Priority).ReadPoints(rendered)
	}, x.runOpts())
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *ReadNode) ReconnectNode(old *bacnetclient.Client, attempt int) (*bacnetclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "bacnet", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *ReadNode) newClient() (*bacnetclient.Client, error) {
	return newClient(x.Config)
}

func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			bacnetOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

func (x *ReadNode) Desc() string {
	return "BACnet/IP client for batch reading object properties. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode BACnet write node
// ------------------------------------------------------------------------------------------------

// WriteNode writes object property values from msg.Data to device, routes via Success on success.
type WriteNode struct {
	base.SharedNode[*bacnetclient.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

func (x *WriteNode) Type() string { return "x/bacnetWrite" }

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:47808",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "setpoint", Addr: "analog-output:0", Type: "FLOAT32", Value: "${msg.value}"},
			},
		},
	}
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no bacnet points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunWrite(ctx, msg, func(client *bacnetclient.Client) error {
		return newDriver(client, x.RuleConfig.Logger, x.Config.Priority).WritePoints(rendered)
	}, x.runOpts())
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *WriteNode) ReconnectNode(old *bacnetclient.Client, attempt int) (*bacnetclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "bacnet", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *WriteNode) newClient() (*bacnetclient.Client, error) {
	return newClient(x.Config)
}

func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			bacnetOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

func (x *WriteNode) Desc() string {
	return "BACnet/IP client for writing object properties. Routes to Success/Failure"
}

func (x *ReadNode) runOpts() iot_points.RunOpts[*bacnetclient.Client] {
	return iot_points.RunOpts[*bacnetclient.Client]{
		Shared:    &x.SharedNode,
		Reconnect: x.ReconnectNode,
		OpLocks:   &bacnetOpLocks,
		Logger:    x.RuleConfig.Logger,
		Prefix:    "[BACnet]",
		// UDP: reconnecting cannot fix a silent device.
		RetryOnTimeout: false,
	}
}

func (x *WriteNode) runOpts() iot_points.RunOpts[*bacnetclient.Client] {
	return iot_points.RunOpts[*bacnetclient.Client]{
		Shared:    &x.SharedNode,
		Reconnect: x.ReconnectNode,
		OpLocks:   &bacnetOpLocks,
		Logger:    x.RuleConfig.Logger,
		Prefix:    "[BACnet]",
		// UDP: reconnecting cannot fix a silent device.
		RetryOnTimeout: false,
	}
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
