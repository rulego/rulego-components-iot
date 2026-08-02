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
	"log"
	"net/textproto"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/errors"
	"github.com/robfig/cron/v3"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/utils/maps"
)

const Type = types.EndpointTypePrefix + "opcua"
const OPC_UA_DATA_MSG_TYPE = "OPC_UA_DATA"

// Endpoint alias
type Endpoint = OpcUa

var _ endpointApi.Endpoint = (*Endpoint)(nil)

// Register component
func init() {
	_ = endpoint.Registry.Register(&Endpoint{})
}

type RequestMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	points     []iot_points.Data
	msg        *types.RuleMsg
	statusCode int
	err        error
}

func (r *RequestMessage) Body() []byte {
	b, err := json.Marshal(r.points)
	if err != nil {
		log.Println(err)
	}
	return b
}

func (r *RequestMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}

func (r *RequestMessage) From() string {
	return ""
}

// GetParam does not provide parameter fetching
func (r *RequestMessage) GetParam(key string) string {
	return ""
}

func (r *RequestMessage) SetMsg(msg *types.RuleMsg) {
	r.msg = msg
}
func (r *RequestMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		// Default to JSON format; if not this type, modify in process function
		ruleMsg := types.NewMsg(0, OPC_UA_DATA_MSG_TYPE, types.JSON, types.NewMetadata(), string(r.Body()))
		r.msg = &ruleMsg
	}
	return r.msg
}

func (r *RequestMessage) SetStatusCode(statusCode int) {
	r.statusCode = statusCode
}
func (r *RequestMessage) SetBody(body []byte) {
	r.body = body
}

// SetError sets error
func (r *RequestMessage) SetError(err error) {

}

// GetError gets error
func (r *RequestMessage) GetError() error {
	return r.err
}

type ResponseMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	points     []iot_points.Data
	msg        *types.RuleMsg
	statusCode int
	err        error
}

func (r *ResponseMessage) Body() []byte {
	b, err := json.Marshal(r.body)
	if err != nil {
		log.Println(err)
	}
	return b
}

func (r *ResponseMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}

func (r *ResponseMessage) From() string {
	return ""
}

// GetParam does not provide parameter fetching
func (r *ResponseMessage) GetParam(key string) string {
	return ""
}

func (r *ResponseMessage) SetMsg(msg *types.RuleMsg) {
	r.msg = msg
}
func (r *ResponseMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		// Default to JSON format; if not this type, modify in process function
		ruleMsg := types.NewMsg(0, OPC_UA_DATA_MSG_TYPE, types.JSON, types.NewMetadata(), string(r.Body()))
		r.msg = &ruleMsg
	}
	return r.msg
}

func (r *ResponseMessage) SetStatusCode(statusCode int) {
	r.statusCode = statusCode
}
func (r *ResponseMessage) SetBody(body []byte) {
	r.body = body
}
func (r *ResponseMessage) getBody() []byte {
	return r.body
}

// SetError sets error
func (r *ResponseMessage) SetError(err error) {

}

// GetError gets error
func (r *ResponseMessage) GetError() error {
	return r.err
}

// OpcUaConfig OPC UA server configuration
type OpcUaConfig struct {
	//OPC UA Server Endpoint, eg. opc.tcp://localhost:4840
	Server string `json:"server" label:"Server" desc:"OPC UA server endpoint, format: opc.tcp://host:port" required:"true" ref:"primary"`
	//Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256
	Policy string `json:"policy" label:"Security Policy" desc:"Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256"`
	//Security Mode: one of None, Sign, SignAndEncrypt
	Mode string `json:"mode" label:"Security Mode" desc:"Security mode: None, Sign, SignAndEncrypt"`
	//Authentication Mode: one of Anonymous, UserName, Certificate
	Auth string `json:"auth" label:"Auth Mode" desc:"Authentication mode: Anonymous, UserName, Certificate"`
	//Authentication Username
	Username string `json:"username" label:"Username" desc:"Authentication username" ref:"shared"`
	//Authentication Password
	Password string `json:"password" label:"Password" desc:"Authentication password" ref:"shared"`
	//OPC UA client certificate file
	CertFile string `json:"certFile" label:"Cert File" desc:"Client certificate file path" ref:"shared"`
	//OPC UA client private key file
	CertKeyFile string `json:"certKeyFile" label:"Cert Key File" desc:"Client private key file path" ref:"shared"`
	// Request timeout in seconds
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	//Interval to read, supports cron expressions
	//example: @every 1m (every 1 minute) 0 0 0 * * * (triggers at midnight)
	Interval string `json:"interval" label:"Interval" desc:"Read interval, supports cron expression, e.g. @every 1m"`
	//NodeIds to read, eg. ns=2;s=Channel1.Device1.Tag1
	NodeIds []string `json:"nodeIds" label:"Node IDs" desc:"OPC UA node IDs to read, e.g. ns=2;s=Channel1.Device1.Tag1"`
}

func (c OpcUaConfig) GetServer() string {
	return c.Server
}
func (c OpcUaConfig) GetPolicy() string {
	return c.Policy
}
func (c OpcUaConfig) GetMode() string {
	return c.Mode
}
func (c OpcUaConfig) GetAuth() string {
	return c.Auth
}
func (c OpcUaConfig) GetUsername() string {
	return c.Username
}
func (c OpcUaConfig) GetPassword() string {
	return c.Password
}
func (c OpcUaConfig) GetCertFile() string {
	return c.CertFile
}
func (c OpcUaConfig) GetCertKeyFile() string {
	return c.CertKeyFile
}
func (c OpcUaConfig) GetTimeout() int {
	return c.Timeout
}

type OpcUa struct {
	impl.BaseEndpoint
	base.SharedNode[*opcua.Client]
	// GracefulShutdown provides graceful shutdown capabilities
	base.GracefulShutdown
	RuleConfig types.Config
	// OPCUA client related configuration
	Config OpcUaConfig
	// Router instance
	Router endpointApi.Router
	// Cron task instance
	cronTask *cron.Cron
	// Cron task ID
	taskId cron.EntryID
}

// Type component type
func (x *OpcUa) Type() string {
	return Type
}

// New creates component instance
func (x *OpcUa) New() types.Node {
	return &OpcUa{
		Config: OpcUaConfig{
			Interval: "@every 1m",
			Server:   "opc.tcp://localhost:4840",
			Policy:   "None",
			Mode:     "none",
			Auth:     "anonymous",
			Timeout:  5,
		},
	}
}

// Init initializes
func (x *OpcUa) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig

	// Initialize graceful shutdown - use reasonable default timeout (10 seconds)
	x.GracefulShutdown.InitGracefulShutdown(x.RuleConfig.Logger, 10*time.Second)

	_ = x.SharedNode.InitWithClose(x.RuleConfig, x.Type(), x.Config.Server, true, func() (*opcua.Client, error) {
		return x.initClient()
	}, func(client *opcua.Client) error {
		if client != nil {
			return client.Close(context.Background())
		}
		return nil
	})
	return err
}

// Destroy destroys
func (x *OpcUa) Destroy() {
	x.GracefulShutdown.GracefulStop(func() {
		_ = x.Close()
	})
}

// Desc returns the component description
func (x *OpcUa) Desc() string {
	return "OPC-UA endpoint for subscribing to node changes and receiving real-time data updates"
}

// Category returns the component category
func (x *OpcUa) Category() string {
	return "endpoint"
}

func (x *OpcUa) Def() types.ComponentForm {
	return types.ComponentForm{
		Desc: "OPC-UA endpoint for subscribing to node changes and receiving real-time data updates",
		RouterForm: &types.RouterForm{
			Hide: true,
		},
	}
}

// GracefulStop provides graceful shutdown for the OPC UA endpoint
func (x *OpcUa) GracefulStop() {
	x.GracefulShutdown.GracefulStop(func() {
		_ = x.Close()
	})
}

func (x *OpcUa) Close() error {
	if x.taskId != 0 && x.cronTask != nil {
		x.cronTask.Remove(x.taskId)
	}
	if x.cronTask != nil {
		x.cronTask.Stop()
	}
	// SharedNode manages client closure through the cleanup function in InitWithClose
	_ = x.SharedNode.Close()
	return nil
}

func (x *OpcUa) Id() string {
	return x.Config.Server
}

func (x *OpcUa) AddRouter(router endpointApi.Router, params ...interface{}) (string, error) {
	if router == nil {
		return "", errors.New("router cannot be nil")
	}
	if x.Router != nil {
		return "", errors.New("duplicate router")
	}
	x.Router = router
	return router.GetId(), nil
}

func (x *OpcUa) RemoveRouter(routerId string, params ...interface{}) error {
	x.Lock()
	defer x.Unlock()
	x.Router = nil
	return nil
}

func (x *OpcUa) Start() error {
	if !x.SharedNode.IsInit() {
		if err := x.SharedNode.InitWithClose(x.RuleConfig, x.Type(), x.Config.Server, true, func() (*opcua.Client, error) {
			return x.initClient()
		}, func(client *opcua.Client) error {
			if client != nil {
				return client.Close(context.Background())
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if x.cronTask != nil {
		x.cronTask.Stop()
	}
	x.cronTask = cron.New(cron.WithChain(cron.Recover(cron.DefaultLogger)), cron.WithLogger(cron.DefaultLogger))
	eid, err := x.cronTask.AddFunc(x.Config.Interval, func() {
		if x.Router != nil {
			_ = x.readNodes(x.Router)
		}
	})
	if err != nil {
		return err
	}
	x.taskId = eid
	x.cronTask.Start()
	return nil
}

func (x *OpcUa) Printf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Printf(format, v...)
	}
}

func (x *OpcUa) readNodes(router endpointApi.Router) error {
	// Increment active operations counter
	x.GracefulShutdown.IncrementActiveOperations()
	defer x.GracefulShutdown.DecrementActiveOperations()

	client, err := x.SharedNode.GetSafely()
	if err != nil {
		x.Printf("get shared client error %v ", err)
		return err
	}

	nodeIds := x.Config.NodeIds
	pts := make([]iot_points.Point, len(nodeIds))
	for i, id := range nodeIds {
		pts[i] = iot_points.Point{Addr: id}
	}
	data, resp, err := opcuaClient.Read(client, nodeIds, x.RuleConfig.Logger)
	if err != nil {
		x.Printf("read nodes error %v ", err)
		return err
	}
	points := opcuaClient.ToPointsData(pts, data, resp)
	exchange := &endpointApi.Exchange{
		In: &RequestMessage{points: points},
		Out: &ResponseMessage{
			points: points,
		}}

	x.DoProcess(context.Background(), router, exchange)
	return nil
}

// initClient initializes client
func (x *OpcUa) initClient() (*opcua.Client, error) {
	return opcuaClient.DefaultHolder(x.Config, x.RuleConfig.Logger).NewOpcUaClient()
}
