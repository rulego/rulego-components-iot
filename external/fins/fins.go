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
	"encoding/json"
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

// finsReconnecter reconnection capability interface.
type finsReconnecter interface {
	reconnect(old *finsclient.Client, attempt int) (*finsclient.Client, error)
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*finsclient.Client, error) {
		return x.Config.initClient()
	}, func(client *finsclient.Client) error {
		if client != nil {
			client.Close()
		}
		return nil
	})
	// Enable same-chain connection pool
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
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no fins points: configure points or pass [{...}] via msg.Data"))
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
			opLock := finsOpLocks.Lock(client)
			opLock.Lock()
			defer opLock.Unlock()
			return newDriver(client).ReadPoints(rendered)
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
			finsOpLocks.Delete(oldClient) // Clean up old connection operation lock
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection.
func (x *ReadNode) reconnect(old *finsclient.Client, attempt int) (*finsclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(finsReconnecter); ok { // cross-type: Read↔Write delegation
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("fins ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		old.Close()
		time.Sleep(iot_points.BackoffFor(attempt))
	}
	newClient, err := x.Config.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[FINS] "+format, v...)
	}
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
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*finsclient.Client, error) {
		return x.Config.initClient()
	}, func(client *finsclient.Client) error {
		if client != nil {
			client.Close()
		}
		return nil
	})
	// Enable same-chain connection pool
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
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no fins points: configure points or pass [{...}] via msg.Data"))
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
			opLock := finsOpLocks.Lock(client)
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
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, lastErr)
			x.SharedNode.SetStatus(types.StatusReconnecting, lastErr.Error())
			oldClient := client
			newClient, rerr := x.reconnect(oldClient, retry)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			finsOpLocks.Delete(oldClient) // Clean up old connection operation lock
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// reconnect safely rebuilds connection (semantics same as ReadNode.reconnect)
func (x *WriteNode) reconnect(old *finsclient.Client, attempt int) (*finsclient.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(finsReconnecter); ok { // cross-type: Read↔Write delegation
					return source.reconnect(old, attempt)
				}
			}
		}
		return nil, fmt.Errorf("fins ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		old.Close()
		time.Sleep(iot_points.BackoffFor(attempt))
	}
	newClient, err := x.Config.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[FINS] "+format, v...)
	}
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
