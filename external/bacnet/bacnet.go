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
	"encoding/json"
	"errors"
	"fmt"
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

// bacnetReconnecter connection rebuild capability interface.
type bacnetReconnecter interface {
	reconnect(old *bacnetclient.Client, attempt int) (*bacnetclient.Client, error)
}

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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*bacnetclient.Client, error) {
		return newClient(x.Config)
	}, closeClient)
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no bacnet points: configure points or pass [{...}] via msg.Data"))
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
		data, rerr := func() ([]iot_points.Data, error) {
			opLock := bacnetOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client, x.RuleConfig.Logger, x.Config.Priority).ReadPoints(rendered)
		}()
		if rerr == nil {
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
		lastErr = rerr
		// BACnet/IP is UDP: reconnecting cannot fix a silent device.
		if iot_points.IsTimeoutErr(rerr) {
			ctx.TellFailure(msg, rerr)
			return
		}
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("read failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, rerr)
			x.SharedNode.SetStatus(types.StatusReconnecting, rerr.Error())
			oldClient := client
			newC, rerr2 := x.reconnect(oldClient, retry)
			if rerr2 != nil {
				ctx.TellFailure(msg, rerr2)
				return
			}
			bacnetOpLocks.Delete(oldClient)
			client = newC
		}
	}
	ctx.TellFailure(msg, lastErr)
}

func (x *ReadNode) reconnect(old *bacnetclient.Client, attempt int) (*bacnetclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(bacnetReconnecter); ok {
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("bacnet ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	_ = closeClient(old)
	time.Sleep(iot_points.BackoffFor(attempt))
	newC, err := newClient(x.Config)
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newC)
	return newC, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[BACnet] "+format, v...)
	}
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*bacnetclient.Client, error) {
		return newClient(x.Config)
	}, closeClient)
	x.SharedNode.BindChain(configuration)
	return err
}

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no bacnet points: configure points or pass [{...}] via msg.Data"))
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
		werr := func() error {
			opLock := bacnetOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client, x.RuleConfig.Logger, x.Config.Priority).WritePoints(rendered)
		}()
		if werr == nil {
			ctx.TellSuccess(msg)
			return
		}
		lastErr = werr
		// BACnet/IP is UDP: reconnecting cannot fix a silent device.
		if iot_points.IsTimeoutErr(werr) {
			ctx.TellFailure(msg, werr)
			return
		}
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, lastErr)
			x.SharedNode.SetStatus(types.StatusReconnecting, lastErr.Error())
			oldClient := client
			newC, rerr := x.reconnect(oldClient, retry)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			bacnetOpLocks.Delete(oldClient)
			client = newC
		}
	}
	ctx.TellFailure(msg, lastErr)
}

func (x *WriteNode) reconnect(old *bacnetclient.Client, attempt int) (*bacnetclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(bacnetReconnecter); ok {
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("bacnet ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	_ = closeClient(old)
	time.Sleep(iot_points.BackoffFor(attempt))
	newC, err := newClient(x.Config)
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newC)
	return newC, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[BACnet] "+format, v...)
	}
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
