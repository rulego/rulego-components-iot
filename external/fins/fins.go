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

// Package fins provides ReadNode and WriteNode for Omron FINS protocol PLCs (CJ/CP/NJ/NX series).
//
// Usage:
//   - Scheduled collection: use endpoint/schedule, configure points below.
//   - On-demand read/write: msg.Data points take precedence (dynamic scenarios).
//
// Point fields support ${msg.xx} / ${metadata.xx} template variables.
package fins

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rulego/rulego"
	finsclient "github.com/rulego/rulego-components-iot/pkg/fins_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// defaultFinsPort default FINS port (UDP and TCP both use 9600)
const defaultFinsPort = 9600

// Register nodes
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// Configuration connection config (shared by read/write nodes)
type Configuration struct {
	// PLC address, format IP or IP:port, FINS default port 9600
	Server string `json:"server" label:"Server" desc:"PLC IP[:port], FINS default port 9600" required:"true" ref:"primary"`
	// Transport: udp (default) or tcp (FINS/TCP with node handshake)
	Transport string `json:"transport" label:"Transport" desc:"transport: udp (default) or tcp (FINS/TCP with node handshake)"`
	// FINS network number (DA1/SA1), default 0
	Network int `json:"network" label:"Network" desc:"FINS network number (DA1/SA1), default 0"`
	// Destination node number (DA2), i.e. PLC FINS node number, default 0
	DstNode int `json:"dstNode" label:"Dest Node" desc:"destination FINS node number (DA2), default 0"`
	// Source node number (SA2), i.e. client FINS node number, default 0
	SrcNode int `json:"srcNode" label:"Source Node" desc:"source FINS node number (SA2), default 0"`
	// Unit address (DA3), CPU unit number, default 0
	Unit int `json:"unit" label:"Unit" desc:"unit address (DA3), default 0"`
	// Request timeout in seconds, default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// Default points table. Used by scheduled collection (schedule trigger); msg.Data points take precedence
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// initClient creates FINS client (UDP by default; transport=tcp uses FINS/TCP with auto handshake).
func (c Configuration) initClient() (*finsclient.Client, error) {
	host, port, err := iot_points.ParseServer(c.Server, defaultFinsPort)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	local := finsclient.NewAddress("0.0.0.0", 0, byte(c.Network), byte(c.SrcNode), 0)
	plc := finsclient.NewAddress(host, port, byte(c.Network), byte(c.DstNode), byte(c.Unit))
	opts := []finsclient.Option{finsclient.WithTimeout(time.Duration(timeout) * time.Second)}
	switch strings.ToLower(strings.TrimSpace(c.Transport)) {
	case "", "udp":
	case "tcp":
		opts = append(opts, finsclient.WithTCP())
	default:
		return nil, fmt.Errorf("fins transport %q: expect udp or tcp", c.Transport)
	}
	return finsclient.NewClient(local, plc, opts...)
}

// finsOpLocks operation locks per underlying client, serializes concurrent read/write with shared client.
var finsOpLocks iot_points.OpLocks

func closeClient(client *finsclient.Client) error {
	if client != nil {
		client.Close()
	}
	return nil
}

// ------------------------------------------------------------------------------------------------
// ReadNode FINS read node
// ------------------------------------------------------------------------------------------------

// ReadNode batch reads FINS points, results (unified Data list) written to msg.Data, routed via Success link.
//
// Input (msg.Data optional): point list JSON, same format as points config. Empty uses configured points.
// Output (msg.Data): [{"name","value","timestamp","error"}] (timestamp in ns; error present only on single-point failure)
type ReadNode struct {
	base.SharedNode[*finsclient.Client]
	Config Configuration
	// reconnectLocker protects reconnection
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/finsRead"
}

// New default configuration
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:    "127.0.0.1:9600",
			Transport: "udp",
			Timeout:   5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "D100", Type: "UINT16"},
			},
		},
	}
}

// Init initializes
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no fins points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunRead(ctx, msg, func(client *finsclient.Client) ([]iot_points.Data, error) {
		return newDriver(client).ReadPoints(rendered)
	}, x.runOpts())
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *ReadNode) ReconnectNode(old *finsclient.Client, attempt int) (*finsclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "fins", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *ReadNode) newClient() (*finsclient.Client, error) {
	return x.Config.initClient()
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // only owner cleans up operation lock
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			finsOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *ReadNode) Desc() string {
	return "Omron FINS client for batch reading PLC points. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode FINS write node
// ------------------------------------------------------------------------------------------------

// WriteNode writes point value list from msg.Data to FINS PLC, routes via Success on success.
//
// Input (msg.Data): [{"name","addr","type","value"}], value supports ${msg.xx}
type WriteNode struct {
	base.SharedNode[*finsclient.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *WriteNode) Type() string {
	return "x/finsWrite"
}

// New default configuration
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:    "127.0.0.1:9600",
			Transport: "udp",
			Timeout:   5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "D100", Type: "UINT16", Value: "${msg.value}"},
			},
		},
	}
}

// Init initializes
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no fins points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunWrite(ctx, msg, func(client *finsclient.Client) error {
		return newDriver(client).WritePoints(rendered)
	}, x.runOpts())
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *WriteNode) ReconnectNode(old *finsclient.Client, attempt int) (*finsclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "fins", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *WriteNode) newClient() (*finsclient.Client, error) {
	return x.Config.initClient()
}

// Destroy cleans up resources
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			finsOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *WriteNode) Desc() string {
	return "Omron FINS client for writing PLC points. Routes to Success/Failure"
}

func (x *ReadNode) runOpts() iot_points.RunOpts[*finsclient.Client] {
	return iot_points.RunOpts[*finsclient.Client]{
		Shared:         &x.SharedNode,
		Reconnect:      x.ReconnectNode,
		OpLocks:        &finsOpLocks,
		Logger:         x.RuleConfig.Logger,
		Prefix:         "[FINS]",
		RetryOnTimeout: true,
	}
}

func (x *WriteNode) runOpts() iot_points.RunOpts[*finsclient.Client] {
	return iot_points.RunOpts[*finsclient.Client]{
		Shared:         &x.SharedNode,
		Reconnect:      x.ReconnectNode,
		OpLocks:        &finsOpLocks,
		Logger:         x.RuleConfig.Logger,
		Prefix:         "[FINS]",
		RetryOnTimeout: true,
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
