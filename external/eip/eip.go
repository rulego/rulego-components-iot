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

// Package eip provides Rockwell ControlLogix/CompactLogix read (ReadNode) and write (WriteNode) nodes via EtherNet/IP (CIP).
//
// Usage:
//   - Scheduled collection: use endpoint/schedule upstream, configure tags in points field.
//   - On-demand read/write: msg.Data with point list takes priority (dynamic scenarios).
//
// All point fields support ${msg.xx} / ${metadata.xx} template variables.
// Since gologix Read requires specific type pointers, points must specify type (BOOL/INT/DINT/REAL/STRING/...).
package eip

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/danomagnum/gologix"
	"github.com/rulego/rulego"
	eipclient "github.com/rulego/rulego-components-iot/pkg/eip_client"
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

// Configuration connection config (shared by read/write nodes)
type Configuration struct {
	// PLC address, format host or host:port, default port 44818
	Server string `json:"server" label:"Server" desc:"host or host:port, default port 44818" required:"true" ref:"primary"`
	// CPU slot on backplane, default 0, auto-generates CIP path
	Slot int `json:"slot" label:"Slot" desc:"CPU slot on backplane, default 0"`
	// Optional: manually override CIP path, e.g. 1,0; empty=auto from slot
	Path string `json:"path" label:"Path" desc:"CIP path override, e.g. 1,0; empty=auto from slot"`
	// Request timeout (seconds), default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// Default points table. Used for scheduled collection (schedule trigger); msg.Data points take precedence
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// GetServer implements eipclient.ConfigProp
func (c Configuration) GetServer() string { return c.Server }

// GetSlot implements eipclient.ConfigProp
func (c Configuration) GetSlot() int { return c.Slot }

// GetPath implements eipclient.ConfigProp
func (c Configuration) GetPath() string { return c.Path }

// GetTimeout implements eipclient.ConfigProp
func (c Configuration) GetTimeout() int { return c.Timeout }

// eipOpLocks associates operation locks by underlying client, serializes concurrent read/write on shared client.
var eipOpLocks iot_points.OpLocks

// eipReconnecter connection rebuild capability interface.
type eipReconnecter interface {
	reconnect(old *gologix.Client, attempt int) (*gologix.Client, error)
}

// ------------------------------------------------------------------------------------------------
// ReadNode EtherNet/IP read node
// ------------------------------------------------------------------------------------------------

// ReadNode batch reads ControlLogix tags, writes results (unified Data list) back to msg.Data, routes via Success.
//
// Input (msg.Data optional): point list JSON, same format as points config. Empty uses configured points.
// Output (msg.Data): [{"name","value","timestamp","error"}] (timestamp in ns; error only present on single-point failure)
type ReadNode struct {
	base.SharedNode[*gologix.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/eipRead"
}

// New default configuration
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:44818",
			Slot:    0,
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "tag1", Addr: "MyTag", Type: "INT32"},
			},
		},
	}
}

// Init initializes
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gologix.Client, error) {
		return eipclient.DefaultHolder(x.Config).NewClient()
	}, func(client *gologix.Client) error {
		if client != nil {
			return client.Disconnect()
		}
		return nil
	})
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes message. Auto reconnect retry maxRetries times on connection-level failure (all tags failed).
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no eip points: configure points or pass [{...}] via msg.Data"))
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
			opLock := eipOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client, x.RuleConfig.Logger).ReadPoints(rendered)
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
			x.SharedNode.SetStatus(types.StatusReconnecting, err.Error())
			oldClient := client
			newClient, rerr := x.reconnect(oldClient, retry)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			eipOpLocks.Delete(oldClient) // clean up old connection operation lock
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection.
func (x *ReadNode) reconnect(old *gologix.Client, attempt int) (*gologix.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(eipReconnecter); ok { // cross-type: Read↔Write both can delegate
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("eip ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		_ = old.Disconnect()
		time.Sleep(iot_points.BackoffFor(attempt))
	}
	newClient, err := eipclient.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[EIP] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // only owner cleans up operation lock
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			eipOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *ReadNode) Desc() string {
	return "EtherNet/IP client for batch reading ControlLogix tags. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode EtherNet/IP write node
// ------------------------------------------------------------------------------------------------

// WriteNode writes tag value list from msg.Data to ControlLogix, routes via Success on success.
//
// Input (msg.Data): [{"name","addr","type","value"}] (addr is CIP tag name), value supports ${msg.xx}
type WriteNode struct {
	base.SharedNode[*gologix.Client]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *WriteNode) Type() string {
	return "x/eipWrite"
}

// New default configuration
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:44818",
			Slot:    0,
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "tag1", Addr: "MyTag", Type: "INT32", Value: "${msg.value}"},
			},
		},
	}
}

// Init initializes
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gologix.Client, error) {
		return eipclient.DefaultHolder(x.Config).NewClient()
	}, func(client *gologix.Client) error {
		if client != nil {
			return client.Disconnect()
		}
		return nil
	})
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes message. Auto reconnect retry maxRetries times on write failure.
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no eip points: configure points or pass [{...}] via msg.Data"))
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
			opLock := eipOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client, x.RuleConfig.Logger).WritePoints(rendered)
		}()
		if werr == nil {
			ctx.TellSuccess(msg)
			return
		} else {
			lastErr = werr
		}
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, lastErr)
			x.SharedNode.SetStatus(types.StatusReconnecting, lastErr.Error())
			oldClient := client
			newClient, rerr := x.reconnect(oldClient, retry)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			eipOpLocks.Delete(oldClient) // clean up old connection operation lock
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection (semantics same as ReadNode.reconnect)
func (x *WriteNode) reconnect(old *gologix.Client, attempt int) (*gologix.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(eipReconnecter); ok { // cross-type: Read↔Write both can delegate
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("eip ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		_ = old.Disconnect()
		time.Sleep(iot_points.BackoffFor(attempt))
	}
	newClient, err := eipclient.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[EIP] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			eipOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *WriteNode) Desc() string {
	return "EtherNet/IP client for writing ControlLogix tags. Routes to Success/Failure"
}
