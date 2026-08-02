/*
 * Copyright 2024 The RuleGo Authors.
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

package opcua

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gopcua/opcua"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// Register node
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
}

// Configuration node configuration
type Configuration struct {
	//OPC UA Server Endpoint, eg. opc.tcp://localhost:4840
	Server string `json:"server" label:"Server" desc:"OPC UA server endpoint, format: opc.tcp://host:port" required:"true" ref:"primary"`
	//Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256
	Policy string `json:"policy" label:"Security Policy" desc:"Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256" ref:"shared" group:"advanced"`
	//Security Mode: one of None, Sign, SignAndEncrypt
	Mode string `json:"mode" label:"Security Mode" desc:"Security mode: None, Sign, SignAndEncrypt" ref:"shared" group:"advanced"`
	//Authentication Mode: one of Anonymous, UserName, Certificate
	Auth     string `json:"auth" label:"Auth Mode" desc:"Authentication mode: Anonymous, UserName, Certificate" ref:"shared" group:"advanced"`
	Username string `json:"username" label:"Username" desc:"Authentication username" ref:"shared" group:"advanced"`
	Password string `json:"password" label:"Password" desc:"Authentication password" ref:"shared" group:"advanced"`
	//OPC UA client certificate file
	CertFile string `json:"certFile" label:"Cert File" desc:"Client certificate file path" ref:"shared" group:"advanced"`
	//OPC UA client private key file
	CertKeyFile string `json:"certKeyFile" label:"Cert Key File" desc:"Client private key file path" ref:"shared" group:"advanced"`
	// Request timeout (seconds)
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5" ref:"shared"`
	// Default points table (addr=NodeID, e.g. ns=2;s=Temperature); empty=parse nodeIds from msg.Data (legacy compatible)
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points; addr=NodeID; empty=parse nodeIds from msg.Data"`
}

func (c Configuration) GetServer() string {
	return c.Server
}
func (c Configuration) GetPolicy() string {
	return c.Policy
}
func (c Configuration) GetMode() string {
	return c.Mode
}
func (c Configuration) GetAuth() string {
	return c.Auth
}
func (c Configuration) GetUsername() string {
	return c.Username
}
func (c Configuration) GetPassword() string {
	return c.Password
}
func (c Configuration) GetCertFile() string {
	return c.CertFile
}
func (c Configuration) GetCertKeyFile() string {
	return c.CertKeyFile
}
func (c Configuration) GetTimeout() int {
	return c.Timeout
}

// ReadNode batch reads OPC UA nodes, results (unified Data list) written back to msg.Data, routed via Success chain.
// gopcua SecureChannel matches responses by RequestID, naturally concurrent-safe, no opLock needed.
//
// Points sources (dual entry, msg.Data takes priority): configure points(addr=NodeID); or msg.Data with nodeIds/points.
// Output(msg.Data): [{"name","value","timestamp","error"}]
//
// opcuaReconnecter connection rebuild capability interface.
type opcuaReconnecter interface {
	reconnect(old *opcua.Client) (*opcua.Client, error)
}

type ReadNode struct {
	base.SharedNode[*opcua.Client]
	// Node configuration
	Config Configuration
	// reconnectLocker protects reconnection
	reconnectLocker sync.Mutex
}

func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:  "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy:  "None",
			Mode:    "none",
			Auth:    "anonymous",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "temperature", Addr: "ns=2;s=Temperature"},
			},
		},
	}
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/opcuaRead"
}

func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	_ = x.SharedNode.InitWithClose(x.RuleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*opcua.Client, error) {
		return x.initClient()
	}, func(client *opcua.Client) error {
		return client.Close(context.Background())
	})
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes messages. Points dual entry (msg.Data takes priority, compatible with legacy nodeIds/legacy write Data/new points); auto reconnect retry on connection-level failure.
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := resolvePoints(x.Config.Points, msg, errors.New("no opcua points: configure points or pass nodeIds/points via msg.Data"))
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
		data, err := newDriver(client, x.RuleConfig.Logger).ReadPoints(rendered)
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
			newClient, rerr := x.reconnect(client)
			if rerr != nil {
				ctx.TellFailure(msg, rerr)
				return
			}
			client = newClient
		}
	}
	ctx.TellFailure(msg, lastErr)
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	_ = x.SharedNode.Close()
}

// Desc returns the component description
func (x *ReadNode) Desc() string {
	return "OPC-UA client for reading node values. Routes to Success/Failure"
}

// Def returns the component form definition
func (x *ReadNode) Def() types.ComponentForm {
	return types.ComponentForm{}
}

func (x *ReadNode) initClient() (*opcua.Client, error) {
	client, err := opcuaClient.DefaultHolder(x.Config, x.RuleConfig.Logger).NewOpcUaClient()
	return client, err
}

// reconnect safely rebuilds connection.
func (x *ReadNode) reconnect(old *opcua.Client) (*opcua.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(opcuaReconnecter); ok { // Cross-type: Read↔Write both can delegate
					return source.reconnect(old)
				}
			}
		}
		return nil, fmt.Errorf("opcua ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
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
		_ = old.Close(context.Background())
		time.Sleep(iot_points.ReconnectDelay)
	}
	newClient, err := x.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *ReadNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[OPCUA] "+format, v...)
	}
}
