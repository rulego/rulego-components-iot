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

// Package snmp provides SNMP (v1/v2c/v3) read (ReadNode) and write (WriteNode) nodes,
// for interfacing with network/facility devices (switches/routers/UPS/sensors etc.).
//
// Usage:
//   - Scheduled collection: use endpoint/schedule upstream, configure OIDs in points field.
//   - On-demand read/write: msg.Data with point list takes priority (dynamic scenarios).
//
// All point fields support ${msg.xx} / ${metadata.xx} template variables.
package snmp

import (
	"errors"
	"sync"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	snmpclient "github.com/rulego/rulego-components-iot/pkg/snmp_client"
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
	// Device address host or host:port
	Server string `json:"server" label:"Server" desc:"host or host:port, default port 161" required:"true" ref:"primary"`
	// SNMP version: v1/v2c/v3, default v2c
	Version string `json:"version" label:"Version" desc:"v1/v2c/v3, default v2c"`
	// community string (v1/v2c)
	Community string `json:"community" label:"Community" desc:"community string for v1/v2c" ref:"shared"`
	// Request timeout (seconds), default 5
	Timeout int `json:"timeout" label:"Timeout" desc:"request timeout in seconds, default 5"`
	// v3 security level: noAuthNoPriv/authNoPriv/authPriv
	SecurityLevel string `json:"securityLevel" label:"Security Level" desc:"v3 only: noAuthNoPriv/authNoPriv/authPriv"`
	// v3 username
	UserName string `json:"username" label:"Username" desc:"v3 only"`
	// v3 auth protocol: None/MD5/SHA/SHA256/SHA512
	AuthProtocol string `json:"authProtocol" label:"Auth Protocol" desc:"v3 only: None/MD5/SHA/SHA256/SHA512"`
	// v3 auth password
	AuthPassword string `json:"authPassword" label:"Auth Password" desc:"v3 only" ref:"shared"`
	// v3 priv protocol: None/DES/AES/AES256
	PrivProtocol string `json:"privProtocol" label:"Priv Protocol" desc:"v3 only: None/DES/AES/AES256"`
	// v3 priv password
	PrivPassword string `json:"privPassword" label:"Priv Password" desc:"v3 only" ref:"shared"`
	// Default points table. Used for scheduled collection (schedule trigger); msg.Data points take precedence
	Points []iot_points.Point `json:"points" label:"Points" desc:"default points table; msg.Data points take precedence"`
}

// ConfigProp interface implementation (GetServer etc. abbreviated to save space)
func (c Configuration) GetServer() string        { return c.Server }
func (c Configuration) GetVersion() string       { return c.Version }
func (c Configuration) GetCommunity() string     { return c.Community }
func (c Configuration) GetTimeout() int          { return c.Timeout }
func (c Configuration) GetSecurityLevel() string { return c.SecurityLevel }
func (c Configuration) GetUsername() string      { return c.UserName }
func (c Configuration) GetAuthProtocol() string  { return c.AuthProtocol }
func (c Configuration) GetAuthPassword() string  { return c.AuthPassword }
func (c Configuration) GetPrivProtocol() string  { return c.PrivProtocol }
func (c Configuration) GetPrivPassword() string  { return c.PrivPassword }

// closeClient closes SNMP client connection
func closeClient(client *gosnmp.GoSNMP) error {
	if client != nil && client.Conn != nil {
		return client.Conn.Close()
	}
	return nil
}

// snmpOpLocks associates operation locks by underlying client, serializes Get/Set/Walk on shared client.
var snmpOpLocks iot_points.OpLocks

// ------------------------------------------------------------------------------------------------
// ReadNode SNMP read node
// ------------------------------------------------------------------------------------------------

// ReadNode batch reads SNMP OIDs (get/walk), writes results (unified Data list) back to msg.Data, routes via Success.
//
// Input (msg.Data optional): point list JSON, same format as points config. Empty uses configured points.
// Output (msg.Data): [{"name","value","timestamp","error"}] (timestamp in ns; error only present on single-point failure;
// walk result name appends actual OID to distinguish same-name subtree nodes)
type ReadNode struct {
	base.SharedNode[*gosnmp.GoSNMP]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *ReadNode) Type() string {
	return "x/snmpRead"
}

// New default configuration
func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: Configuration{
			Server:        "127.0.0.1:161",
			Version:       "v2c",
			Community:     "public",
			Timeout:       5,
			SecurityLevel: "noAuthNoPriv",
			AuthProtocol:  "None",
			PrivProtocol:  "None",
			Points: []iot_points.Point{
				{Name: "sysName", Addr: "1.3.6.1.2.1.1.5.0"},
			},
		},
	}
}

// Init initializes
func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes message. Retry/reconnect handled by the shared runner (UDP: timeouts fail fast).
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no snmp points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunRead(ctx, msg, func(client *gosnmp.GoSNMP) ([]iot_points.Data, error) {
		return newDriver(client, x.RuleConfig.Logger).ReadPoints(rendered)
	}, x.runOpts())
}

func (x *ReadNode) runOpts() iot_points.RunOpts[*gosnmp.GoSNMP] {
	return iot_points.RunOpts[*gosnmp.GoSNMP]{
		Shared:    &x.SharedNode,
		Reconnect: x.ReconnectNode,
		OpLocks:   &snmpOpLocks,
		Logger:    x.RuleConfig.Logger,
		Prefix:    "[SNMP]",
	}
}

func (x *ReadNode) newClient() (*gosnmp.GoSNMP, error) {
	return snmpclient.DefaultHolder(x.Config).NewClient()
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *ReadNode) ReconnectNode(old *gosnmp.GoSNMP, attempt int) (*gosnmp.GoSNMP, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "snmp", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

// Destroy cleans up resources
func (x *ReadNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // only owner cleans up operation lock
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			snmpOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *ReadNode) Desc() string {
	return "SNMP client for batch reading OIDs (get/walk). Routes to Success/Failure"
}

// ------------------------------------------------------------------------------------------------
// WriteNode SNMP write node
// ------------------------------------------------------------------------------------------------

// WriteNode writes OID value list from msg.Data to device (Set), routes via Success on success.
//
// Input (msg.Data): [{"name","addr","type","value"}] (addr is OID like "1.3.6.1..."), value supports ${msg.xx}
type WriteNode struct {
	base.SharedNode[*gosnmp.GoSNMP]
	Config          Configuration
	reconnectLocker sync.Mutex
}

// Type returns component type
func (x *WriteNode) Type() string {
	return "x/snmpWrite"
}

// New default configuration
func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: Configuration{
			Server:        "127.0.0.1:161",
			Version:       "v2c",
			Community:     "public",
			Timeout:       5,
			SecurityLevel: "noAuthNoPriv",
			AuthProtocol:  "None",
			PrivProtocol:  "None",
			Points: []iot_points.Point{
				{Name: "sysLocation", Addr: "1.3.6.1.2.1.1.6.0", Type: "OctetString", Value: "${msg.value}"},
			},
		},
	}
}

// Init initializes
func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, x.newClient, closeClient)
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

// OnMsg processes message. Retry/reconnect handled by the shared runner.
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	pts, err := iot_points.ResolvePoints(x.Config.Points, msg, errors.New("no snmp points: configure points or pass [{...}] via msg.Data"))
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	rendered := renderPoints(ctx, msg, pts)
	iot_points.RunWrite(ctx, msg, func(client *gosnmp.GoSNMP) error {
		return newDriver(client, x.RuleConfig.Logger).WritePoints(rendered)
	}, x.runOpts())
}

func (x *WriteNode) runOpts() iot_points.RunOpts[*gosnmp.GoSNMP] {
	return iot_points.RunOpts[*gosnmp.GoSNMP]{
		Shared:    &x.SharedNode,
		Reconnect: x.ReconnectNode,
		OpLocks:   &snmpOpLocks,
		Logger:    x.RuleConfig.Logger,
		Prefix:    "[SNMP]",
	}
}

func (x *WriteNode) newClient() (*gosnmp.GoSNMP, error) {
	return snmpclient.DefaultHolder(x.Config).NewClient()
}

// ReconnectNode lets ref:// borrowers delegate to the connection owner, or rebuilds the client.
func (x *WriteNode) ReconnectNode(old *gosnmp.GoSNMP, attempt int) (*gosnmp.GoSNMP, error) {
	if x.SharedNode.IsFromPool() {
		return iot_points.BorrowerReconnect(x.RuleConfig.NodePool, x.SharedNode.InstanceId, "snmp", old, attempt)
	}
	return iot_points.RebuildConn(&x.reconnectLocker, x.SharedNode.GetSafely, x.SharedNode.Refresh, old, attempt, x.newClient, closeClient)
}

// Destroy cleans up resources
func (x *WriteNode) Destroy() {
	if !x.SharedNode.IsFromPool() {
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			snmpOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc component description
func (x *WriteNode) Desc() string {
	return "SNMP client for writing OIDs (set). Routes to Success/Failure"
}

// renderPoints renders ${msg.xx}/${metadata.xx} templates in point fields.
func renderPoints(ctx types.RuleContext, msg types.RuleMsg, pts []iot_points.Point) []iot_points.Point {
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	rendered := make([]iot_points.Point, len(pts))
	for i := range pts {
		rendered[i] = iot_points.RenderPoint(pts[i], env)
	}
	return rendered
}
