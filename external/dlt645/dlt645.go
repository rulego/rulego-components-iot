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

// Package dlt645 node layer: DL/T 645-2007 power meter read nodes.
//
// Usage:
//   - Scheduled collection: use endpoint/schedule, configure points below (addr=Data ID DI).
//   - On-demand read: msg.Data points take precedence (dynamic scenarios).
//
// Point fields support ${msg.xx} / ${metadata.xx} template variables.
package dlt645

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// Register nodes
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// Configuration DLT645 read node configuration
type Configuration struct {
	// TCP address, format host:port (tcp:// prefix optional)
	Server string `json:"server" label:"Server" desc:"TCP address, host:port (tcp:// prefix optional)" required:"true" ref:"primary"`
	// Meter address: 12-digit decimal BCD, e.g. 000000000001
	Addr string `json:"addr" label:"Meter Address" desc:"12-digit BCD meter address, e.g. 000000000001" required:"true"`
	// Request timeout in seconds, default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// Default points table. addr=Data ID DI (e.g. "00-01-00-00"); msg.Data points take precedence
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// dlt645OpLocks operation locks per connection.
var dlt645OpLocks iot_points.OpLocks

// closeClient closes the meter connection.
func closeClient(conn net.Conn) error {
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// ReadNode batch reads DLT645 power meter points, results (unified Data list) written to msg.Data, routed via Success link.
//
// Input (msg.Data optional): point list JSON, same format as points config (addr=DI). Empty uses configured points.
// Output (msg.Data): [{"name","value","timestamp"}]
type ReadNode struct {
	base.SharedNode[net.Conn]
	Config Configuration
	// reconnectLocker protects reconnection
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/dlt645Read"
}

// New default configuration
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:8899",
			Addr:    "000000000001",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "total_active_energy", Addr: "00-01-00-00"},
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

// OnMsg handles messages. Retry/reconnect handled by the shared runner.
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no dlt645 points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunRead(ctx, msg, func(conn net.Conn) ([]iot_points.Data, error) {
		return newDriver(conn, x.Config.Addr, x.timeout()).ReadPoints(rendered)
	}, x.runOpts())
}

func (x *ReadNode) runOpts() iot_points.RunOpts[net.Conn] {
	return iot_points.RunOpts[net.Conn]{
		Shared:         &x.SharedNode,
		Reconnect:      x.ReconnectNode,
		OpLocks:        &dlt645OpLocks,
		Logger:         x.RuleConfig.Logger,
		Prefix:         "[DLT645]",
		RetryOnTimeout: true,
	}
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *ReadNode) ReconnectNode(old net.Conn, attempt int) (net.Conn, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "dlt645", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *ReadNode) newClient() (net.Conn, error) {
	return dialTCP(x.Config.Server, x.Config.Timeout)
}

// timeout request timeout, default 5 seconds
func (x *ReadNode) timeout() time.Duration {
	t := x.Config.Timeout
	if t <= 0 {
		t = iot_points.DefaultTimeoutSec
	}
	return time.Duration(t) * time.Second
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // only owner cleans up operation lock
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			dlt645OpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *ReadNode) Desc() string {
	return "DL/T 645-2007 power meter client for batch reading points. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode DL/T 645 write node
// ------------------------------------------------------------------------------------------------

// WriteNode sends write data item commands to meter (e.g. write time, address, parameters).
//
// Input (msg.Data): point list JSON [{"name","addr","type","value"}], addr=DI Data ID.
type WriteNode struct {
	base.SharedNode[net.Conn]
	Config          Configuration
	reconnectLocker sync.Mutex
}

func (x *WriteNode) Type() string { return "x/dlt645Write" }

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:8899",
			Addr:    "000000000001",
			Timeout: 5,
		},
	}
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Retry/reconnect handled by the shared runner (write also
// serializes on the connection op lock so reads and writes cannot interleave frames).
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no dlt645 write points: pass [{\"addr\",\"type\",\"value\"}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunWrite(ctx, msg, func(conn net.Conn) error {
		return newDriver(conn, x.Config.Addr, x.timeout()).WritePoints(rendered)
	}, x.runOpts())
}

func (x *WriteNode) runOpts() iot_points.RunOpts[net.Conn] {
	return iot_points.RunOpts[net.Conn]{
		Shared:         &x.SharedNode,
		Reconnect:      x.ReconnectNode,
		OpLocks:        &dlt645OpLocks,
		Logger:         x.RuleConfig.Logger,
		Prefix:         "[DLT645]",
		RetryOnTimeout: true,
	}
}

// timeout request timeout, default 5 seconds
func (x *WriteNode) timeout() time.Duration {
	t := x.Config.Timeout
	if t <= 0 {
		t = iot_points.DefaultTimeoutSec
	}
	return time.Duration(t) * time.Second
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *WriteNode) ReconnectNode(old net.Conn, attempt int) (net.Conn, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "dlt645", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

func (x *WriteNode) newClient() (net.Conn, error) {
	return dialTCP(x.Config.Server, x.Config.Timeout)
}

func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			dlt645OpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

func (x *WriteNode) Desc() string {
	return "DL/T 645-2007 power meter client for writing data items. Routes to Success/Failure"
}

// dialTCP establishes TCP connection. server may have tcp:// prefix.
func dialTCP(server string, timeoutSec int) (net.Conn, error) {
	addr := strings.TrimPrefix(strings.TrimSpace(server), "tcp://")
	if addr == "" {
		return nil, errors.New("dlt645: empty server address")
	}
	t := timeoutSec
	if t <= 0 {
		t = iot_points.DefaultTimeoutSec
	}
	return net.DialTimeout("tcp", addr, time.Duration(t)*time.Second)
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
