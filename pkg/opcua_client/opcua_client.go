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

package opcuaClient

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/rulego/rulego/api/types"
)

const OPC_UA_DATA_MSG_TYPE = "OPC_UA_DATA"

var logger = types.DefaultLogger()

// Data OPC数据封装结构体
type Data struct {
	DisplayName string      `json:"displayName"`
	NodeId      string      `json:"nodeId"`
	RecordTime  time.Time   `json:"recordTime"`
	SourceTime  time.Time   `json:"sourceTime"`
	Value       interface{} `json:"value"`
	Quality     uint32      `json:"quality"`
	FloatValue  float64     `json:"floatValue"`
	Timestamp   time.Time   `json:"timestamp"`
}

// ParseValue 解析数据FloatValue
func (d *Data) ParseValue() (*Data, error) {
	var err error
	if d != nil && d.Value != nil {
		switch d.Value.(type) {
		case int:
			d.FloatValue = float64(d.Value.(int))
		case int16:
			d.FloatValue = float64(d.Value.(int16))
		case int32:
			d.FloatValue = float64(d.Value.(int32))
		case int64:
			d.FloatValue = float64(d.Value.(int64))
		case uint16:
			d.FloatValue = float64(d.Value.(uint16))
		case uint32:
			d.FloatValue = float64(d.Value.(uint32))
		case float32:
			d.FloatValue = float64(d.Value.(float32))
		case float64:
			d.FloatValue = d.Value.(float64)
		case byte:
			s := string(d.Value.(byte))
			parseBool, err := strconv.ParseBool(s)
			if err == nil {
				if parseBool {
					d.FloatValue = 1
				} else {
					d.FloatValue = 0
				}
			}
		case bool:
			if d.Value.(bool) {
				d.FloatValue = 1
			} else {
				d.FloatValue = 0
			}
		default:
			return nil, errors.New(fmt.Sprintf("Type conversion is not supported : %v", d))
		}
	} else {
		err = errors.New("Data value is nil")
	}
	if err != nil {
		return d, err
	}
	return d, nil
}

// ConfigProp 统一OPCUA客户端初始化参数接口
type ConfigProp interface {
	// GetServer 获取OPCUA服务地址
	GetServer() string
	// GetPolicy 获取OPCUA安全策略
	GetPolicy() string
	// GetMode 获取OPCUA安全模式
	GetMode() string
	// GetAuth 获取OPCUA认证方式
	GetAuth() string
	// GetUsername 获取OPCUA认证用户名
	GetUsername() string
	// GetPassword 获取OPCUA认证密码
	GetPassword() string
	// GetCertFile 获取OPCUA证书文件
	GetCertFile() string
	// GetCertKeyFile 获取OPCUA证书私钥文件
	GetCertKeyFile() string
}

// OpcUaClientHolder OPCUA客户端相关配置
type OpcUaClientHolder struct {
	// Config OPC客户端配置
	Config ConfigProp
	// Ctx 上下文
	Ctx context.Context
	// Logger 日志
	Logger types.Logger
}

// Printf 日志输出
func (x *OpcUaClientHolder) Printf(format string, v ...interface{}) {
	x.Logger.Printf(format, v...)
}

// DefaultHolder 默认配置
func DefaultHolder(c ConfigProp) *OpcUaClientHolder {
	return &OpcUaClientHolder{
		Config: c,
		Ctx:    context.Background(),
		Logger: logger,
	}
}

// NewOpcUaClient 创建OPCUA客户端
func (x *OpcUaClientHolder) NewOpcUaClient() (*opcua.Client, error) {
	// Get a list of the endpoints for our target server
	endpoints, err := opcua.GetEndpoints(x.Ctx, x.Config.GetServer())
	if err != nil {
		x.Printf("opcua get endpoints error : %v ", err)
		return nil, err
	}
	// Get the options to pass into the client based on the flags passed into the executable
	opts := x.createOptions(endpoints)
	// Create a Client with the selected options
	c, err := opcua.NewClient(x.Config.GetServer(), opts...)
	if err != nil {
		x.Printf("opcua new client error : %v ", err)
		return nil, err
	}
	if err := c.Connect(x.Ctx); err != nil {
		x.Printf("connect opcua client error : %v ", err)
		return nil, err
	}
	return c, nil
}

// createOptions 构建Options
func (x *OpcUaClientHolder) createOptions(endpoints []*ua.EndpointDescription) []opcua.Option {

	opts := []opcua.Option{}
	var cert []byte
	var privateKey *rsa.PrivateKey
	if x.Config.GetCertFile() != "" && x.Config.GetCertKeyFile() != "" {
		x.Printf("Loading cert/key from %s/%s", x.Config.GetCertFile, x.Config.GetCertKeyFile)
		c, err := tls.LoadX509KeyPair(x.Config.GetCertFile(), x.Config.GetCertKeyFile())
		if err != nil {
			x.Printf("Failed to load certificate: %v", err)
		} else {
			pk, ok := c.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				x.Printf("Invalid private key")
			}
			cert = c.Certificate[0]
			privateKey = pk
			opts = append(opts, opcua.PrivateKey(pk), opcua.Certificate(cert))
		}
	}

	var secPolicy string
	switch {
	case x.Config.GetPolicy() == "auto":
		// set it later
	case strings.HasPrefix(x.Config.GetPolicy(), ua.SecurityPolicyURIPrefix):
		secPolicy = x.Config.GetPolicy()
	case x.Config.GetPolicy() == "None" || x.Config.GetPolicy() == "Basic128Rsa15" || x.Config.GetPolicy() == "Basic256" || x.Config.GetPolicy() == "Basic256Sha256" || x.Config.GetPolicy() == "Aes128_Sha256_RsaOaep" || x.Config.GetPolicy() == "Aes256_Sha256_RsaPss":
		secPolicy = ua.SecurityPolicyURIPrefix + x.Config.GetPolicy()
	default:
		x.Printf("Invalid security policy: %s", x.Config.GetPolicy())
	}

	// Select the most appropriate authentication mode from server capabilities and user input
	authMode, authOptions := x.authOption(cert, privateKey)
	opts = append(opts, authOptions...)

	var secMode ua.MessageSecurityMode
	switch strings.ToLower(x.Config.GetMode()) {
	case "auto":
	case "none":
		secMode = ua.MessageSecurityModeNone
	case "sign":
		secMode = ua.MessageSecurityModeSign
	case "signandencrypt":
		secMode = ua.MessageSecurityModeSignAndEncrypt
	default:
		x.Printf("Invalid security mode: %s", x.Config.GetMode)
	}

	// Allow input of only one of sec-mode,sec-policy when choosing 'None'
	if secMode == ua.MessageSecurityModeNone || secPolicy == ua.SecurityPolicyURINone {
		secMode = ua.MessageSecurityModeNone
		secPolicy = ua.SecurityPolicyURINone
	}

	// Find the best endpoint based on our input and server recommendation (highest SecurityMode+SecurityLevel)
	var serverEndpoint *ua.EndpointDescription
	switch {
	case x.Config.GetMode() == "auto" && x.Config.GetPolicy() == "auto": // No user selection, choose best
		for _, e := range endpoints {
			if serverEndpoint == nil || (e.SecurityMode >= serverEndpoint.SecurityMode && e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	case x.Config.GetMode() != "auto" && x.Config.GetPolicy() == "auto": // User only cares about mode, select highest securitylevel with that mode
		for _, e := range endpoints {
			if e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	case x.Config.GetMode() == "auto" && x.Config.GetPolicy() != "auto": // User only cares about policy, select highest securitylevel with that policy
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	default: // User cares about both
		fmt.Println("secMode: ", secMode, "secPolicy:", secPolicy)
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	}

	if serverEndpoint == nil { // Didn't find an endpoint with matching policy and mode.
		x.Printf("unable to find suitable server endpoint with selected sec-policy and sec-mode")
		x.printEndpointOptions(endpoints)
		x.Printf("quitting")
	}

	secPolicy = serverEndpoint.SecurityPolicyURI
	secMode = serverEndpoint.SecurityMode

	// Check that the selected endpoint is a valid combo
	err := x.validateEndpointConfig(endpoints, secPolicy, secMode, authMode)
	if err != nil {
		x.Printf("error validating input: %s", err)
	}

	opts = append(opts, opcua.SecurityFromEndpoint(serverEndpoint, authMode))

	x.Printf("Using config:\nEndpoint: %s\nSecurity mode: %s, %s\nAuth mode : %s\n", serverEndpoint.EndpointURL, serverEndpoint.SecurityPolicyURI, serverEndpoint.SecurityMode, authMode)
	return opts
}

func (x *OpcUaClientHolder) authOption(cert []byte, pk *rsa.PrivateKey) (ua.UserTokenType, []opcua.Option) {

	var authMode ua.UserTokenType
	var authOptions []opcua.Option
	switch strings.ToLower(x.Config.GetAuth()) {
	case "anonymous":
		authMode = ua.UserTokenTypeAnonymous
		authOptions = append(authOptions, opcua.AuthAnonymous())

	case "username":
		authMode = ua.UserTokenTypeUserName
		authOptions = append(authOptions, opcua.AuthUsername(x.Config.GetUsername(), x.Config.GetPassword()))

	case "certificate":
		authMode = ua.UserTokenTypeCertificate
		// Note: You should still use these two Config options to load the auth certificate and private key
		// separately from the secure channel configuration even if the same certificate is used for both purposes
		authOptions = append(authOptions, opcua.AuthCertificate(cert))
		authOptions = append(authOptions, opcua.AuthPrivateKey(pk))

	case "issuedtoken":
		// todo: this is unsupported, fail here or fail in the opcua package?
		authMode = ua.UserTokenTypeIssuedToken
		authOptions = append(authOptions, opcua.AuthIssuedToken([]byte(nil)))

	default:
		x.Printf("unknown auth-mode, defaulting to Anonymous")
		authMode = ua.UserTokenTypeAnonymous
		authOptions = append(authOptions, opcua.AuthAnonymous())

	}

	return authMode, authOptions
}

func (x *OpcUaClientHolder) validateEndpointConfig(endpoints []*ua.EndpointDescription, secPolicy string, secMode ua.MessageSecurityMode, authMode ua.UserTokenType) error {
	for _, e := range endpoints {
		if e.SecurityMode == secMode && e.SecurityPolicyURI == secPolicy {
			for _, t := range e.UserIdentityTokens {
				if t.TokenType == authMode {
					return nil
				}
			}
		}
	}

	err := fmt.Errorf("server does not support an endpoint with security : %s , %s, %s", secPolicy, secMode, authMode)
	x.printEndpointOptions(endpoints)
	return err
}

func (x *OpcUaClientHolder) printEndpointOptions(endpoints []*ua.EndpointDescription) {
	x.Printf("Valid options for the endpoint are:")
	x.Printf("         sec-policy    |    sec-mode     |      auth-modes\n")
	x.Printf("-----------------------|-----------------|---------------------------\n")
	for _, e := range endpoints {
		p := strings.TrimPrefix(e.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#")
		m := strings.TrimPrefix(e.SecurityMode.String(), "MessageSecurityMode")
		var tt []string
		for _, t := range e.UserIdentityTokens {
			tok := strings.TrimPrefix(t.TokenType.String(), "UserTokenType")

			// Just show one entry if a server has multiple varieties of one TokenType (eg. different algorithms)
			dup := false
			for _, v := range tt {
				if tok == v {
					dup = true
					break
				}
			}
			if !dup {
				tt = append(tt, tok)
			}
		}
		x.Printf("%22s | %-15s | (%s)", p, m, strings.Join(tt, ","))
	}
}

// Read 读取点位数据
func Read(client *opcua.Client, nodeIds []string) ([]Data, *ua.ReadResponse, error) {
	ctx := context.Background()
	allIds := make([]*ua.ReadValueID, 0)
	data := make([]Data, 0)

	for _, nodeId := range nodeIds {
		id, err := ua.ParseNodeID(nodeId)
		if err != nil {
			logger.Printf("parse node id error %v ", err)
			return nil, nil, err
		} else {
			allIds = append(allIds, &ua.ReadValueID{NodeID: id})
		}
		n := client.Node(id)
		lt, err := n.DisplayName(ctx)
		if err != nil {
			logger.Printf("fetch node displayName error : %v ,nodeId : %v  ", err, nodeId)
			return nil, nil, err
		}
		data = append(data, Data{NodeId: id.String(), DisplayName: lt.Text})
	}

	req := &ua.ReadRequest{
		MaxAge:             1000,
		NodesToRead:        allIds,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}
	var resp *ua.ReadResponse
	resp, err := client.Read(ctx, req)
	if err != nil {
		logger.Printf("point read error", err)
		return nil, nil, err
	} else {
		for i, result := range resp.Results {
			if result != nil && result.Status != ua.StatusOK {
				logger.Printf("read node with bad status : %v  ", result.Status)
			} else {
				d := Data{
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
			}
		}
	}
	return data, resp, nil
}
