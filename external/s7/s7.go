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

// Package s7 provides Siemens S7 PLC read (ReadNode) and write (WriteNode) nodes.
//
// Usage:
//   - Scheduled collection: use endpoint/schedule upstream, configure points in points field.
//   - On-demand read/write: msg.Data with point list takes priority (dynamic scenarios).
//
// All point fields support ${msg.xx} / ${metadata.xx} template variables.
package s7

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/robinson/gos7"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	s7client "github.com/rulego/rulego-components-iot/pkg/s7_client"
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
	// PLC address, format host:port, ISO-on-TCP default port 102
	Server string `json:"server" label:"Server" desc:"host:port, default port 102" required:"true" ref:"primary"`
	// Rack number, default 0
	Rack int `json:"rack" label:"Rack" desc:"rack number, default 0"`
	// CPU slot: S7-1200/1500/200SMART=1, S7-300/400=2
	Slot int `json:"slot" label:"Slot" desc:"CPU slot: S7-1200/1500/200SMART=1, S7-300/400=2"`
	// Request timeout (seconds), default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// Default points table. Used for scheduled collection (schedule trigger); msg.Data points take precedence
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// Point point at node config layer. Fields are strings to support ${msg.xx} template variables.
// GetServer implements s7client.ConfigProp
func (c Configuration) GetServer() string { return c.Server }

// GetRack implements s7client.ConfigProp
func (c Configuration) GetRack() int { return c.Rack }

// GetSlot implements s7client.ConfigProp
func (c Configuration) GetSlot() int { return c.Slot }

// GetTimeout implements s7client.ConfigProp
func (c Configuration) GetTimeout() int { return c.Timeout }

// s7OpLocks associates operation locks by underlying handler, serializes concurrent read/write on shared handler.
var s7OpLocks iot_points.OpLocks

// s7Reconnecter connection rebuild capability interface.
type s7Reconnecter interface {
	reconnect(old *gos7.TCPClientHandler, attempt int) (*gos7.TCPClientHandler, error)
}

// ------------------------------------------------------------------------------------------------
// ReadNode S7 read node
// ------------------------------------------------------------------------------------------------

// ReadNode batch reads S7 points, writes results (unified Data list) back to msg.Data, routes via Success.
//
// Input (msg.Data optional): point list JSON, same format as points config. Empty uses configured points.
// Output (msg.Data): [{"name","value","timestamp","error"}] (timestamp in ns; error only present on single-point failure)
type ReadNode struct {
	base.SharedNode[*gos7.TCPClientHandler]
	Config Configuration
	// reconnectLocker protects reconnect
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/s7Read"
}

// New default configuration
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:102",
			Rack:    0,
			Slot:    1,
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "DB1.DBD0", Type: "FLOAT32"},
			},
		},
	}
}

// Init initializes
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gos7.TCPClientHandler, error) {
		return s7client.DefaultHolder(x.Config).NewHandler()
	}, func(handler *gos7.TCPClientHandler) error {
		if handler != nil {
			return handler.Close()
		}
		return nil
	})
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes message. Auto reconnect retry maxRetries times on connection-level failure (all points failed).
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	handler, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no s7 points: configure points or pass [{...}] via msg.Data"))
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
			opLock := s7OpLocks.Lock(handler)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(handler, x.RuleConfig.Logger).ReadPoints(rendered)
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
			oldHandler := handler
			newHandler, rerr := x.reconnect(oldHandler, retry)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			s7OpLocks.Delete(oldHandler) // clean up old connection operation lock
			handler = newHandler
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection.
func (x *ReadNode) reconnect(old *gos7.TCPClientHandler, attempt int) (*gos7.TCPClientHandler, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(s7Reconnecter); ok { // cross-type: Read↔Write both can delegate
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("s7 ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		time.Sleep(iot_points.BackoffFor(attempt))
	}
	newHandler, err := s7client.DefaultHolder(x.Config).NewHandler()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newHandler)
	return newHandler, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[S7] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // only owner cleans up operation lock
		if h, err := x.SharedNode.GetSafely(); err == nil && h != nil {
			s7OpLocks.Delete(h)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *ReadNode) Desc() string {
	return "S7 client for batch reading PLC points. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode S7 write node
// ------------------------------------------------------------------------------------------------

// WriteNode writes point value list from msg.Data to S7 PLC, routes via Success on success.
//
// Input (msg.Data): [{"name","addr","type","value"}] (addr is Siemens address like "DB1.DBD0"/"M0.1"), value supports ${msg.xx}
type WriteNode struct {
	base.SharedNode[*gos7.TCPClientHandler]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *WriteNode) Type() string {
	return "x/s7Write"
}

// New default configuration
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:102",
			Rack:    0,
			Slot:    1,
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "DB1.DBD0", Type: "FLOAT32", Value: "${msg.value}"},
			},
		},
	}
}

// Init initializes
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gos7.TCPClientHandler, error) {
		return s7client.DefaultHolder(x.Config).NewHandler()
	}, func(handler *gos7.TCPClientHandler) error {
		if handler != nil {
			return handler.Close()
		}
		return nil
	})
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes message. Auto reconnect retry maxRetries times on write failure.
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	handler, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no s7 points: configure points or pass [{...}] via msg.Data"))
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
			opLock := s7OpLocks.Lock(handler)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(handler, x.RuleConfig.Logger).WritePoints(rendered)
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
			oldHandler := handler
			newHandler, rerr := x.reconnect(oldHandler, retry)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			s7OpLocks.Delete(oldHandler) // clean up old connection operation lock
			handler = newHandler
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection (semantics same as ReadNode.reconnect)
func (x *WriteNode) reconnect(old *gos7.TCPClientHandler, attempt int) (*gos7.TCPClientHandler, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(s7Reconnecter); ok { // cross-type: Read↔Write both can delegate
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("s7 ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		time.Sleep(iot_points.BackoffFor(attempt))
	}
	newHandler, err := s7client.DefaultHolder(x.Config).NewHandler()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newHandler)
	return newHandler, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[S7] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if h, err := x.SharedNode.GetSafely(); err == nil && h != nil {
			s7OpLocks.Delete(h)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *WriteNode) Desc() string {
	return "S7 client for writing PLC points. Routes to Success/Failure"
}
