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
	"encoding/json"
	"errors"
	"fmt"
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

// dlt645Reconnecter reconnection capability interface.
type dlt645Reconnecter interface {
	reconnect(old net.Conn) (net.Conn, error)
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (net.Conn, error) {
		return dialTCP(x.Config.Server, x.Config.Timeout)
	}, func(conn net.Conn) error {
		if conn != nil {
			return conn.Close()
		}
		return nil
	})
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Connection-level failure (all points failed) auto-reconnects with maxRetries.
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	conn, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no dlt645 points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rendered := make([]iot_points.Point, len(pts))
	for i := range pts {
		rendered[i] = iot_points.RenderPoint(pts[i], env)
	}
	var lastErr error
	for retry := 0; retry <= iot_points.DefaultMaxRetries; retry++ {
		data, err := func() ([]iot_points.Data, error) {
			opLock := dlt645OpLocks.Lock(conn)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(conn, x.Config.Addr, x.timeout()).ReadPoints(rendered)
		}()
		if err == nil {
			b, mErr := json.Marshal(data)
			if mErr != nil {
				ctx.TellFailure(msg, mErr)
				return
			}
			msg.SetDataType(types.JSON)
			msg.SetData(string(b))
			ctx.TellSuccess(msg)
			return
		}
		lastErr = err
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("read failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, err)
			oldConn := conn
			newConn, rerr := x.reconnect(oldConn)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			dlt645OpLocks.Delete(oldConn) // Clean up old connection operation lock
			conn = newConn
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// timeout request timeout, default 5 seconds
func (x *ReadNode) timeout() time.Duration {
	t := x.Config.Timeout
	if t <= 0 {
		t = iot_points.DefaultTimeoutSec
	}
	return time.Duration(t) * time.Second
}

// reconnect safely rebuilds connection.
func (x *ReadNode) reconnect(old net.Conn) (net.Conn, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(dlt645Reconnecter); ok {
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("dlt645 ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
	}
	x.reconnectLocker.Lock()
	defer x.reconnectLocker.Unlock()
	current, err := x.SharedNode.GetSafely()
	if err != nil {
		return nil, err
	}
	if current != old {
		return current, nil
	}
	if old != nil {
		_ = old.Close()
		time.Sleep(iot_points.ReconnectDelay)
	}
	newConn, err := dialTCP(x.Config.Server, x.Config.Timeout)
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newConn)
	return newConn, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[DLT645] "+format, v...)
	}
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (net.Conn, error) {
		return dialTCP(x.Config.Server, x.Config.Timeout)
	}, func(conn net.Conn) error {
		if conn != nil {
			return conn.Close()
		}
		return nil
	})
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	conn, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no dlt645 write points: pass [{\"addr\",\"type\",\"value\"}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rendered := make([]iot_points.Point, len(pts))
	for i := range pts {
		rendered[i] = iot_points.RenderPoint(pts[i], env)
	}
	d := newDriver(conn, x.Config.Addr, time.Duration(x.Config.Timeout)*time.Second)
	if err := d.WritePoints(rendered); err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	ctx.TellSuccess(msg)
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
