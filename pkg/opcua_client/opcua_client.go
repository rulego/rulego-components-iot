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
	"strings"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

const OPC_UA_DATA_MSG_TYPE = "OPC_UA_DATA"

// Data OPC UA data encapsulation structure
type Data struct {
	DisplayName string      `json:"displayName"`
	NodeId      string      `json:"nodeId"`
	RecordTime  time.Time   `json:"recordTime"`
	SourceTime  time.Time   `json:"sourceTime"`
	Value       interface{} `json:"value"`
	Quality     uint32      `json:"quality"`
	FloatValue  float64     `json:"floatValue"`
	Timestamp   time.Time   `json:"timestamp"`
	DataType    string      `json:"dataType"`
}

// ParseValue parses data FloatValue. On unsupported/nil values it returns (d, err) rather than
// (nil, err) so callers can still use the receiver. Array values leave FloatValue at 0 (the unified
// ToPointsData path preserves arrays via ScaleValue, which passes non-numeric values through).
func (d *Data) ParseValue() (*Data, error) {
	if d == nil || d.Value == nil {
		return d, errors.New("Data value is nil")
	}
	switch v := d.Value.(type) {
	case int:
		d.FloatValue = float64(v)
	case int16:
		d.FloatValue = float64(v)
	case int32:
		d.FloatValue = float64(v)
	case int64:
		d.FloatValue = float64(v)
	case uint16:
		d.FloatValue = float64(v)
	case uint32:
		d.FloatValue = float64(v)
	case float32:
		d.FloatValue = float64(v)
	case float64:
		d.FloatValue = v
	case byte:
		d.FloatValue = float64(v)
	case bool:
		if v {
			d.FloatValue = 1
		} else {
			d.FloatValue = 0
		}
	default:
		// Arrays and other complex types: leave FloatValue as-is (0) and report unsupported.
		return d, fmt.Errorf("Type conversion is not supported : %v", d.Value)
	}
	return d, nil
}

// ConfigProp unified OPC UA client initialization parameter interface
type ConfigProp interface {
	// GetServer gets OPC UA service address
	GetServer() string
	// GetPolicy gets OPC UA security policy
	GetPolicy() string
	// GetMode gets OPC UA security mode
	GetMode() string
	// GetAuth gets OPC UA authentication method
	GetAuth() string
	// GetUsername gets OPC UA authentication username
	GetUsername() string
	// GetPassword gets OPC UA authentication password
	GetPassword() string
	// GetCertFile gets OPC UA certificate file
	GetCertFile() string
	// GetCertKeyFile gets OPC UA certificate private key file
	GetCertKeyFile() string
	// GetTimeout gets request timeout (seconds), <=0 uses default 5 seconds
	GetTimeout() int
}

// OpcUaClientHolder OPC UA client related configuration
type OpcUaClientHolder struct {
	// Config OPC client configuration
	Config ConfigProp
	// Ctx context
	Ctx context.Context
	// Logger logger
	Logger types.Logger
	// endpointOptionsPrinted tracks whether endpoint options have been printed
	endpointOptionsPrinted bool
}

// Printf log output
func (x *OpcUaClientHolder) Printf(format string, v ...interface{}) {
	if x.Logger != nil {
		x.Logger.Printf(format, v...)
	}
}

// DefaultHolder default configuration
func DefaultHolder(c ConfigProp, logger types.Logger) *OpcUaClientHolder {
	return &OpcUaClientHolder{
		Config: c,
		Ctx:    context.Background(),
		Logger: logger,
	}
}

// NewOpcUaClient creates OPC UA client
func (x *OpcUaClientHolder) NewOpcUaClient() (*opcua.Client, error) {
	if x.Config == nil {
		return nil, errors.New("config is nil")
	}
	// Get a list of the endpoints for our target server
	endpoints, err := opcua.GetEndpoints(x.Ctx, x.Config.GetServer())
	if err != nil {
		return nil, err
	}
	// Get the options to pass into the client based on the flags passed into the executable
	opts := x.createOptions(endpoints)
	// Request timeout, <=0 uses default 5 seconds
	timeout := x.Config.GetTimeout()
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	opts = append(opts, opcua.RequestTimeout(time.Duration(timeout)*time.Second))
	// Create a Client with the selected options
	c, err := opcua.NewClient(x.Config.GetServer(), opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(x.Ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// createOptions builds Options
func (x *OpcUaClientHolder) createOptions(endpoints []*ua.EndpointDescription) []opcua.Option {
	if x.Config == nil {
		return []opcua.Option{}
	}

	if len(endpoints) == 0 {
		return []opcua.Option{}
	}

	opts := []opcua.Option{}
	var cert []byte
	var privateKey *rsa.PrivateKey
	if x.Config.GetCertFile() != "" && x.Config.GetCertKeyFile() != "" {
		c, err := tls.LoadX509KeyPair(x.Config.GetCertFile(), x.Config.GetCertKeyFile())
		if err == nil {
			if pk, ok := c.PrivateKey.(*rsa.PrivateKey); ok {
				cert = c.Certificate[0]
				privateKey = pk
				opts = append(opts, opcua.PrivateKey(pk), opcua.Certificate(cert))
			}
		}
	}

	var secPolicy string
	policyLower := strings.ToLower(x.Config.GetPolicy())
	switch {
	case policyLower == "auto":
		// set it later
	case strings.HasPrefix(x.Config.GetPolicy(), ua.SecurityPolicyURIPrefix):
		secPolicy = x.Config.GetPolicy()
	case policyLower == "none":
		secPolicy = ua.SecurityPolicyURIPrefix + "None"
	case policyLower == "basic128rsa15":
		secPolicy = ua.SecurityPolicyURIPrefix + "Basic128Rsa15"
	case policyLower == "basic256":
		secPolicy = ua.SecurityPolicyURIPrefix + "Basic256"
	case policyLower == "basic256sha256":
		secPolicy = ua.SecurityPolicyURIPrefix + "Basic256Sha256"
	case policyLower == "aes128_sha256_rsaoaep":
		secPolicy = ua.SecurityPolicyURIPrefix + "Aes128_Sha256_RsaOaep"
	case policyLower == "aes256_sha256_rsapss":
		secPolicy = ua.SecurityPolicyURIPrefix + "Aes256_Sha256_RsaPss"
	default:
		// Invalid security policy, secPolicy remains empty
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
		// Invalid security mode, will use default
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
		x.Printf("selecting endpoint by secMode: %s, secPolicy: %s", secMode, secPolicy)
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	}

	if serverEndpoint == nil { // Didn't find an endpoint with matching policy and mode.
		// log endpoint options only on first failure
		if !x.endpointOptionsPrinted && x.Logger != nil {
			x.Printf("unable to find suitable server endpoint with selected sec-policy and sec-mode")
			x.printEndpointOptions(endpoints)
			x.endpointOptionsPrinted = true
		}
		return []opcua.Option{}
	}

	secPolicy = serverEndpoint.SecurityPolicyURI
	secMode = serverEndpoint.SecurityMode

	// Check that the selected endpoint is a valid combo
	err := x.validateEndpointConfig(endpoints, secPolicy, secMode, authMode)
	if err != nil {
		return []opcua.Option{}
	}

	opts = append(opts, opcua.SecurityFromEndpoint(serverEndpoint, authMode))
	return opts
}

func (x *OpcUaClientHolder) authOption(cert []byte, pk *rsa.PrivateKey) (ua.UserTokenType, []opcua.Option) {
	if x.Config == nil {
		return ua.UserTokenTypeAnonymous, []opcua.Option{opcua.AuthAnonymous()}
	}

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
		// Unknown auth-mode, default to Anonymous
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

	// log endpoint options only on first failure
	if !x.endpointOptionsPrinted && x.Logger != nil {
		x.Printf("OPC UA endpoint validation failed: %v", err)
		x.printEndpointOptions(endpoints)
		x.endpointOptionsPrinted = true
	}

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

// Read reads point data. data[i]/resp.Results[i] stay index-aligned with nodeIds[i] so that
// ToPointsData can map results back to the input points by position.
//
// Failure handling:
//   - A NodeID that fails to parse aborts the batch (returns the error). This preserves the
//     1:1 positional alignment that ToPointsData relies on; callers validate NodeIDs up-front.
//   - A DisplayName fetch failure (RPC error, or a non-compliant server returning an unexpected
//     variant that gopcua would otherwise panic on) is non-fatal: DisplayName is left empty and
//     the read continues. ToPointsData falls back to the configured Name/Addr.
func Read(client *opcua.Client, nodeIds []string, logger types.Logger) ([]Data, *ua.ReadResponse, error) {
	ctx := context.Background()
	allIds := make([]*ua.ReadValueID, 0, len(nodeIds))
	data := make([]Data, 0, len(nodeIds))

	for _, nodeId := range nodeIds {
		id, err := ua.ParseNodeID(nodeId)
		if err != nil {
			if logger != nil {
				logger.Warnf("parse node id %q error: %v", nodeId, err)
			}
			return nil, nil, err
		}
		allIds = append(allIds, &ua.ReadValueID{NodeID: id})
		data = append(data, Data{NodeId: id.String(), DisplayName: safeDisplayName(client, id, ctx)})
	}

	req := &ua.ReadRequest{
		MaxAge:             1000,
		NodesToRead:        allIds,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}
	resp, err := client.Read(ctx, req)
	if err != nil {
		if logger != nil {
			logger.Warnf("point read error: %v", err)
		}
		return nil, nil, err
	}
	for i, result := range resp.Results {
		// gopcua keeps resp.Results 1:1 with NodesToRead (hence with data), but guard against a
		// malformed server returning extra results to avoid an out-of-range panic on data[i].
		if i >= len(data) {
			break
		}
		if result != nil && result.Status == ua.StatusOK {
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
	return data, resp, nil
}

// safeDisplayName returns the node's DisplayName text, or "" if the attribute cannot be read or
// the server returns an unexpected variant type. gopcua's DisplayName performs an unchecked type
// assertion (v.Value().(*ua.LocalizedText)) that panics on a nil/unexpected value, so recover
// here to keep a single bad node from crashing the acquisition process.
func safeDisplayName(client *opcua.Client, id *ua.NodeID, ctx context.Context) (text string) {
	defer func() {
		if r := recover(); r != nil {
			text = ""
		}
	}()
	lt, err := client.Node(id).DisplayName(ctx)
	if err != nil || lt == nil {
		return ""
	}
	return lt.Text
}

// ToPointsData converts Read results to unified iot_points.Data list. Shared by read node and acquisition endpoint.
// points and resp.Results are aligned by index (Name/Addr for naming, Scale/Offset for engineering conversion).
// Name priority: points[i].Name → DisplayName → points[i].Addr.
// Non-OK points marked Error; OK points filled with Value and ServerTimestamp(ns).
func ToPointsData(points []iot_points.Point, data []Data, resp *ua.ReadResponse) []iot_points.Data {
	out := make([]iot_points.Data, 0, len(points))
	for i, result := range resp.Results {
		var p iot_points.Point
		if i < len(points) {
			p = points[i]
		}
		name := p.Name
		if name == "" && i < len(data) && data[i].DisplayName != "" {
			name = data[i].DisplayName
		}
		if name == "" {
			name = p.Addr
		}
		dd := iot_points.Data{Name: name}
		switch {
		case result != nil && result.Status == ua.StatusOK:
			dd.Value = iot_points.ScaleValue(result.Value.Value(), p)
			// Prefer SourceTimestamp (when the value was actually generated); many embedded/edge
			// servers populate only SourceTimestamp and leave ServerTimestamp zero, so fall back to
			// ServerTimestamp. If both are zero, Timestamp stays 0; downstream tsdbWrite treats 0 as "current time".
			if t := result.SourceTimestamp; !t.IsZero() {
				dd.Timestamp = t.UnixNano()
			} else if t := result.ServerTimestamp; !t.IsZero() {
				dd.Timestamp = t.UnixNano()
			}
		case result != nil:
			dd.Error = result.Status.Error()
		default:
			dd.Error = "nil read result"
		}
		out = append(out, dd)
	}
	return out
}
