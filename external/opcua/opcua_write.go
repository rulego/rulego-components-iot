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
	"errors"
	"fmt"
	"strings"
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
	_ = rulego.Registry.Register(&WriteNode{})
}

// WriteNodeConfiguration node configuration
type WriteNodeConfiguration struct {
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
	// Default points table (addr=NodeID); empty=parse from msg.Data (legacy compatible)
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points; addr=NodeID; empty=parse from msg.Data"`
}

func (c WriteNodeConfiguration) GetServer() string {
	return c.Server
}
func (c WriteNodeConfiguration) GetPolicy() string {
	return c.Policy
}
func (c WriteNodeConfiguration) GetMode() string {
	return c.Mode
}
func (c WriteNodeConfiguration) GetAuth() string {
	return c.Auth
}
func (c WriteNodeConfiguration) GetUsername() string {
	return c.Username
}
func (c WriteNodeConfiguration) GetPassword() string {
	return c.Password
}
func (c WriteNodeConfiguration) GetCertFile() string {
	return c.CertFile
}
func (c WriteNodeConfiguration) GetCertKeyFile() string {
	return c.CertKeyFile
}
func (c WriteNodeConfiguration) GetTimeout() int {
	return c.Timeout
}

// WriteNode writes point values to OPC UA server. Routes to Success on success, Failure otherwise.
//
// Points sources (dual entry, msg.Data takes priority): configure points(addr=NodeID); or msg.Data with points/legacy {nodeId,value} list.
type WriteNode struct {
	base.SharedNode[*opcua.Client]
	// Node configuration
	Config WriteNodeConfiguration
	// reconnectLocker protects reconnection
	reconnectLocker sync.Mutex
}

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: WriteNodeConfiguration{
			Server:  "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy:  "None",
			Mode:    "none",
			Auth:    "anonymous",
			Timeout: 5,
			Points: []iot_points.Point{
				{Name: "setpoint", Addr: "ns=2;s=Setpoint", Type: "FLOAT64", Value: "${msg.value}"},
			},
		},
	}
}

// Type returns component type
func (x *WriteNode) Type() string {
	return "x/opcuaWrite"
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	_ = x.SharedNode.InitWithClose(x.RuleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*opcua.Client, error) {
		return x.initClient()
	}, func(client *opcua.Client) error {
		return client.Close(context.Background())
	})
	// Enable same-chain connection pool: local connections registered to chain directory by node ID
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes messages. Points dual entry (msg.Data takes priority, compatible with legacy write Data/legacy read nodeIds/new points); auto reconnect retry on write failure.
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	pts, err := resolvePoints(x.Config.Points, msg, errors.New("no opcua points: configure points or pass points via msg.Data"))
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
		if werr := newDriver(client, x.RuleConfig.Logger).WritePoints(rendered); werr == nil {
			ctx.TellSuccess(msg)
			return
		} else {
			lastErr = werr
		}
		if retry < iot_points.DefaultMaxRetries {
			x.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, iot_points.DefaultMaxRetries, lastErr)
			x.SharedNode.SetStatus(types.StatusReconnecting, lastErr.Error())
			newClient, rerr := x.reconnect(client, retry)
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
func (x *WriteNode) Destroy() {
	_ = x.SharedNode.Close()
}

// Desc returns the component description
func (x *WriteNode) Desc() string {
	return "OPC-UA client for writing node values. Routes to Success/Failure"
}

// Def returns the component form definition
func (x *WriteNode) Def() types.ComponentForm {
	return types.ComponentForm{}
}

func (x *WriteNode) initClient() (*opcua.Client, error) {
	client, err := opcuaClient.DefaultHolder(x.Config, x.RuleConfig.Logger).NewOpcUaClient()
	return client, err
}

// reconnect safely rebuilds connection.
func (x *WriteNode) reconnect(old *opcua.Client, attempt int) (*opcua.Client, error) {
	if x.SharedNode.IsFromPool() {
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if source, ok := nodeCtx.GetNode().(opcuaReconnecter); ok { // Cross-type: Read↔Write both can delegate
					return source.reconnect(old, attempt)
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
		time.Sleep(iot_points.BackoffFor(attempt))
	}
	newClient, err := x.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

func (x *WriteNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[OPCUA] "+format, v...)
	}
}

// castValue attempts to convert []interface{} to a slice of a specific type so that ua.NewVariant can handle it correctly
func castValue(val interface{}, dataType string) interface{} {
	if dataType != "" {
		return castValueByType(val, dataType)
	}
	switch v := val.(type) {
	case []interface{}:
		if len(v) == 0 {
			return v
		}
		// Convert based on first element type
		// Convert based on the type of the first element
		switch v[0].(type) {
		case float64:
			arr := make([]float64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = f
				} else {
					return val // If types are inconsistent, return the original value
				}
			}
			return arr
		case string:
			arr := make([]string, len(v))
			for i, e := range v {
				if s, ok := e.(string); ok {
					arr[i] = s
				} else {
					return val
				}
			}
			return arr
		case bool:
			arr := make([]bool, len(v))
			for i, e := range v {
				if b, ok := e.(bool); ok {
					arr[i] = b
				} else {
					return val
				}
			}
			return arr
		}
	}
	return val
}

func castValueByType(val interface{}, dataType string) interface{} {
	dataType = strings.ToLower(dataType)
	// Check if array type
	// Check if it is an array type
	if v, ok := val.([]interface{}); ok {
		switch dataType {
		case "boolean":
			arr := make([]bool, len(v))
			for i, e := range v {
				if b, ok := e.(bool); ok {
					arr[i] = b
				}
			}
			return arr
		case "sbyte":
			arr := make([]int8, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int8(f)
				}
			}
			return arr
		case "byte":
			arr := make([]byte, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = byte(f)
				}
			}
			return arr
		case "int16":
			arr := make([]int16, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int16(f)
				}
			}
			return arr
		case "uint16":
			arr := make([]uint16, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = uint16(f)
				}
			}
			return arr
		case "int32":
			arr := make([]int32, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int32(f)
				}
			}
			return arr
		case "uint32":
			arr := make([]uint32, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = uint32(f)
				}
			}
			return arr
		case "int64":
			arr := make([]int64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = int64(f)
				}
			}
			return arr
		case "uint64":
			arr := make([]uint64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = uint64(f)
				}
			}
			return arr
		case "float":
			arr := make([]float32, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = float32(f)
				}
			}
			return arr
		case "double":
			arr := make([]float64, len(v))
			for i, e := range v {
				if f, ok := e.(float64); ok {
					arr[i] = f
				}
			}
			return arr
		case "string":
			arr := make([]string, len(v))
			for i, e := range v {
				if s, ok := e.(string); ok {
					arr[i] = s
				}
			}
			return arr
		case "datetime":
			arr := make([]time.Time, len(v))
			for i, e := range v {
				if s, ok := e.(string); ok {
					if t, err := time.Parse(time.RFC3339, s); err == nil {
						arr[i] = t
					}
				}
			}
			return arr
		}
	}

	// Scalar type processing
	// Scalar type handling
	switch dataType {
	case "boolean":
		if v, ok := val.(bool); ok {
			return v
		}
	case "sbyte":
		if v, ok := val.(float64); ok {
			return int8(v)
		}
	case "byte":
		if v, ok := val.(float64); ok {
			return byte(v)
		}
	case "int16":
		if v, ok := val.(float64); ok {
			return int16(v)
		}
	case "uint16":
		if v, ok := val.(float64); ok {
			return uint16(v)
		}
	case "int32":
		if v, ok := val.(float64); ok {
			return int32(v)
		}
	case "uint32":
		if v, ok := val.(float64); ok {
			return uint32(v)
		}
	case "int64":
		if v, ok := val.(float64); ok {
			return int64(v)
		}
	case "uint64":
		if v, ok := val.(float64); ok {
			return uint64(v)
		}
	case "float":
		if v, ok := val.(float64); ok {
			return float32(v)
		}
	case "double":
		if v, ok := val.(float64); ok {
			return v
		}
	case "string":
		if v, ok := val.(string); ok {
			return v
		}
	case "datetime":
		if v, ok := val.(string); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				return t
			}
		}
	case "guid":
		if v, ok := val.(string); ok {
			// To support GUID, need to implement ParseGUID or use third-party library
			// Temporarily remove ParseGUID call to avoid compilation error
			// if id, err := ua.ParseGUID(v); err == nil {
			// 	return *id
			// }
			return v
		}
	}
	return val
}
