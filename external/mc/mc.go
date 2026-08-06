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

// Package mc provides ReadNode and WriteNode for Mitsubishi MC Protocol (3E frame, binary) PLCs,
// applicable to Q/L/R/iQ-R/iQ-F series.
//
// Usage:
//   - Scheduled collection: use endpoint/schedule, configure points below.
//   - On-demand read/write: msg.Data points take precedence (dynamic scenarios).
//
// Point Addr is Mitsubishi device address: word devices D100/W10/R200/ZR10/TN5, bit devices M0/X1F/Y0/B4.
// Point fields support ${msg.xx} / ${metadata.xx} template variables.
package mc

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/moge800/gomcprotocol"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// defaultPort MC protocol default port
const defaultPort = 6000

// Register nodes
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
	_ = rulego.Registry.Register(&WriteNode{})
}

// Configuration connection config (shared by read/write nodes).
// Note: station numbers like network/PC are fixed by underlying library to local (00/FF/FF03/00), covering Ethernet direct connection.
type Configuration struct {
	// PLC address in host:port format, default port 6000
	Server string `json:"server" label:"Server" desc:"Mitsubishi PLC host:port, MC default port 6000" required:"true" ref:"primary"`
	// Request timeout in seconds, default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// Default point list. Used when schedule triggered; msg.Data points take priority
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// mcOpLocks operation locks per underlying client, serializes concurrent read/write with shared client.
var mcOpLocks iot_points.OpLocks

// newClient creates and connects 3E frame binary client.
func newClient(config Configuration) (*gomcprotocol.Client3E, error) {
	host, port, err := iot_points.ParseServer(config.Server, defaultPort)
	if err != nil {
		return nil, err
	}
	client, err := gomcprotocol.New3EClient(host, port, gomcprotocol.ModeBinary)
	if err != nil {
		return nil, err
	}
	if config.Timeout > 0 {
		client.SetTimeout(time.Duration(config.Timeout) * time.Second)
	}
	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

// mcReconnecter reconnection capability interface.
type mcReconnecter interface {
	reconnect(old *gomcprotocol.Client3E, attempt int) (*gomcprotocol.Client3E, error)
}

// ------------------------------------------------------------------------------------------------
// ReadNode MC read node
// ------------------------------------------------------------------------------------------------

// ReadNode batch reads Mitsubishi PLC points, results (unified Data list) written to msg.Data, routed via Success link.
//
// Input (msg.Data optional): point list JSON, same format as points config. Empty uses configured points.
// Output (msg.Data): [{"name","value","timestamp","error"}]
type ReadNode struct {
	base.SharedNode[*gomcprotocol.Client3E]
	Config Configuration
	// reconnectLocker protects reconnection
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/mcRead"
}

// New default configuration
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "127.0.0.1:6000",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "D100", Type: "UINT16"},
			},
		},
	}
}

// Init initializes
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gomcprotocol.Client3E, error) {
		return newClient(x.Config)
	}, func(client *gomcprotocol.Client3E) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	// Enable chain-scoped connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Connection-level failure (all points failed) auto-reconnects with maxRetries.
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no mc points: configure points or pass [{...}] via msg.Data"))
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
			opLock := mcOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client).ReadPoints(rendered)
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
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("read failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, rerr)
			x.SharedNode.SetStatus(types.StatusReconnecting, rerr.Error())
			oldClient := client
			newClient, cerr := x.reconnect(oldClient, retry)
			if cerr != nil {
				ctx.TellFailure(msg, cerr)
				return
			}
			mcOpLocks.Delete(oldClient)
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection.
func (x *ReadNode) reconnect(old *gomcprotocol.Client3E, attempt int) (*gomcprotocol.Client3E, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(mcReconnecter); ok {
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("mc ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	client, err := newClient(x.Config)
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(client)
	return client, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[MC] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			mcOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *ReadNode) Desc() string {
	return "Mitsubishi MC protocol client for batch reading PLC points. Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode MC write node
// ------------------------------------------------------------------------------------------------

// WriteNode writes point value list from msg.Data to Mitsubishi PLC, routes via Success on success.
//
// Input (msg.Data): [{"name","addr","type","value"}], value supports ${msg.xx}
type WriteNode struct {
	base.SharedNode[*gomcprotocol.Client3E]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *WriteNode) Type() string {
	return "x/mcWrite"
}

// New default configuration
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:  "127.0.0.1:6000",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "point1", Addr: "D100", Type: "UINT16", Value: "${msg.value}"},
			},
		},
	}
}

// Init initializes
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*gomcprotocol.Client3E, error) {
		return newClient(x.Config)
	}, func(client *gomcprotocol.Client3E) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	// Enable chain-scoped connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Write failure auto-reconnects with maxRetries.
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no mc points: configure points or pass [{...}] via msg.Data"))
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
			opLock := mcOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client).WritePoints(rendered)
		}()
		if werr == nil {
			ctx.TellSuccess(msg)
			return
		}
		lastErr = werr
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, werr)
			x.SharedNode.SetStatus(types.StatusReconnecting, werr.Error())
			oldClient := client
			newClient, cerr := x.reconnect(oldClient, retry)
			if cerr != nil {
				ctx.TellFailure(msg, cerr)
				return
			}
			mcOpLocks.Delete(oldClient)
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection (semantics same as ReadNode.reconnect)
func (x *WriteNode) reconnect(old *gomcprotocol.Client3E, attempt int) (*gomcprotocol.Client3E, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(mcReconnecter); ok {
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("mc ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	client, err := newClient(x.Config)
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(client)
	return client, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[MC] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			mcOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *WriteNode) Desc() string {
	return "Mitsubishi MC protocol client for writing PLC points. Routes to Success/Failure"
}
