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
	"fmt"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/rulego/rulego"
	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// Register the node
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
}

// Configuration: node configuration
type Configuration struct {
	//OPC UA Server Endpoint, eg. opc.tcp://localhost:4840
	Server string `json:"server" label:"Server" desc:"OPC UA server endpoint, format: opc.tcp://host:port" required:"true" ref:"primary"`
	//Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256
	Policy string `json:"policy" label:"Security Policy" desc:"Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256"`
	//Security Mode: one of None, Sign, SignAndEncrypt
	Mode string `json:"mode" label:"Security Mode" desc:"Security mode: None, Sign, SignAndEncrypt"`
	//Authentication Mode: one of Anonymous, UserName, Certificate
	Auth     string `json:"auth" label:"Auth Mode" desc:"Authentication mode: Anonymous, UserName, Certificate"`
	Username string `json:"username" label:"Username" desc:"Authentication username" ref:"shared"`
	Password string `json:"password" label:"Password" desc:"Authentication password" ref:"shared"`
	//OPC UA Server CertFile Path
	CertFile string `json:"certFile" label:"Cert File" desc:"Client certificate file path" ref:"shared"`
	//OPC UA Server CertKeyFile Path
	CertKeyFile string `json:"certKeyFile" label:"Cert Key File" desc:"Client private key file path" ref:"shared"`
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

// ReadNode opcua reads nodes
// Query message load msg.Data node list point data
// Node list format: [ "ns=3;i=1003","ns=3;i=1005" ]
// The query results will be reassigned to msg.Data, passed to the next node via the `Success` chain
// Result format:
// [
//
//	 {
//	   "displayName": "ns=3;i=1003",
//	   "floatValue": 0,
//	   "nodeId": "ns=3;i=1003",
//	   "quality": 0,
//	   "recordTime": "0001-01-01T00:00:00Z",
//	   "sourceTime": "0001-01-01T00:00:00Z",
//	   "timestamp": "0001-01-01T00:00:00Z",
//	}
//
// ]
type ReadNode struct {
	base.SharedNode[*opcua.Client]
	//Node configuration
	Config Configuration
}

func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server: "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy: "None",
			Mode:   "none",
			Auth:   "anonymous",
		},
	}
}

// Type returns the component type
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
	return err
}

// OnMsg implements the Node interface to process messages
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	nodeIds := make([]string, 0)
	err = json.Unmarshal([]byte(msg.GetData()), &nodeIds)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	data, resp, err := opcuaClient.Read(client, nodeIds)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	succ := false
	errs := make([]string, 10)
	for i, result := range resp.Results {
		if result != nil && result.Status != ua.StatusOK {
			if len(errs) < 10 {
				//Prevent excessive search results
				errs = append(errs, result.Status.Error())
			}
		} else {
			d := opcuaClient.Data{
				DisplayName: data[i].DisplayName,
				NodeId:      data[i].NodeId,
				RecordTime:  result.ServerTimestamp,
				SourceTime:  result.SourceTimestamp,
				Value:       result.Value.Value(),
				Quality:     uint32(result.Status),
				Timestamp:   time.Now(),
			}
			_, _ = d.ParseValue()
			data[i] = d
			succ = true
		}
	}
	if succ {
		if dbyte, err := json.Marshal(data); err != nil {
			ctx.TellFailure(msg, err)
		} else {
			msg.SetData(string(dbyte))
			ctx.TellSuccess(msg)
		}
	} else {
		ctx.TellFailure(msg, fmt.Errorf("read failed: %q ", errs))
	}
}

// Destroy to clean up resources
func (x *ReadNode) Destroy() {
	_ = x.SharedNode.Close()
}

// Desc returns the component description
func (x *ReadNode) Desc() string {
	return "OPC-UA client for reading node values. Routes to Success/Failure"
}

func (x *ReadNode) initClient() (*opcua.Client, error) {
	client, err := opcuaClient.DefaultHolder(x.Config).NewOpcUaClient()
	return client, err
}
