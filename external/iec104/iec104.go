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
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rulego/rulego"
	iec104client "github.com/rulego/rulego-components-iot/pkg/iec104_client"
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

// iec104Reconnecter reconnection capability interface.
type iec104Reconnecter interface {
	reconnect(old *iec104client.Client) (*iec104client.Client, error)
}

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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*iec104client.Client, error) {
		return iec104client.DefaultHolder(x.Config).NewClient()
	}, func(client *iec104client.Client) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	// Enable same-chain connection pool: local connections registered to chain directory by node ID, for chain-internal ref:// borrowing
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Connection-level failure auto-reconnects with maxRetries.
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no iec104 points: configure points or pass [{...}] via msg.Data"))
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
		data, rerr := newDriver(client).ReadPoints(rendered)
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
			oldClient := client
			newClient, cerr := x.reconnect(oldClient)
			if cerr != nil {
				ctx.TellFailure(msg, cerr)
				return
			}
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection.
func (x *ReadNode) reconnect(old *iec104client.Client) (*iec104client.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(iec104Reconnecter); ok {
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("iec104 ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	newClient, err := iec104client.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[IEC104] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*iec104client.Client, error) {
		return iec104client.DefaultHolder(x.Config).NewClient()
	}, func(client *iec104client.Client) error {
		if client != nil {
			return client.Close()
		}
		return nil
	})
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg handles messages. Parse point list from msg.Data, send control commands point by point. Write failure auto-reconnects.
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no iec104 write points: pass [{\"addr\",\"type\",\"value\"}] via msg.Data"))
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
		werr := newDriver(client).WritePoints(rendered)
		if werr == nil {
			ctx.TellSuccess(msg)
			return
		}
		lastErr = werr
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, werr)
			oldClient := client
			newClient, cerr := x.reconnect(oldClient)
			if cerr != nil {
				ctx.TellFailure(msg, cerr)
				return
			}
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection (semantics same as ReadNode.reconnect)
func (x *WriteNode) reconnect(old *iec104client.Client) (*iec104client.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(iec104Reconnecter); ok {
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("iec104 ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
	newClient, err := iec104client.DefaultHolder(x.Config).NewClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[IEC104] "+format, v...)
	}
}

// Destroy cleans up resources
func (x *WriteNode) Destroy() {
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *WriteNode) Desc() string {
	return "IEC 60870-5-104 master for control commands (single/double/setpoint). Routes to Success/Failure"
}
