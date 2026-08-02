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

// Package hj212 provides HJ212 (HJ 212-2017 pollution online monitoring data transmission standard) passive receiver endpoint:
// Listens TCP port, receives device-initiated frames, parses pollutant factors into unified iot_points.Data for rule chain processing.
// Passive collection only, does not actively respond to devices (Flag bit0 response handled by downstream rules).
package hj212

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/textproto"
	"strconv"
	"sync"
	"time"

	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/utils/maps"
)

const Type = types.EndpointTypePrefix + "hj212"
const HJ212MsgType = "HJ212"

// Frame field injection key for msg.Metadata, downstream uses ${metadata.xx} to get value
const (
	MetadataKeyFrom     = "from"
	MetadataKeyMN       = "mn"
	MetadataKeyST       = "st"
	MetadataKeyCN       = "cn"
	MetadataKeyDataTime = "dataTime"
)

// Endpoint alias
type Endpoint = HJ212Endpoint

var _ endpointApi.Endpoint = (*Endpoint)(nil)

// Register endpoint
func init() {
	_ = endpoint.Registry.Register(&Endpoint{})
}

// RequestMessage wraps parsed point data from one frame
type RequestMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	msg        *types.RuleMsg
	from       string
	statusCode int
	err        error
}

func (r *RequestMessage) Body() []byte { return r.body }
func (r *RequestMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}
func (r *RequestMessage) From() string               { return r.from }
func (r *RequestMessage) GetParam(key string) string { return "" }
func (r *RequestMessage) SetMsg(msg *types.RuleMsg)  { r.msg = msg }
func (r *RequestMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		ruleMsg := types.NewMsg(0, HJ212MsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *RequestMessage) SetStatusCode(c int) { r.statusCode = c }
func (r *RequestMessage) SetBody(b []byte)    { r.body = b }
func (r *RequestMessage) SetError(err error)  { r.err = err }
func (r *RequestMessage) GetError() error     { return r.err }

// ResponseMessage response message (passive receiver does not use, placeholder to satisfy interface)
type ResponseMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	msg        *types.RuleMsg
	statusCode int
	err        error
}

func (r *ResponseMessage) Body() []byte { return r.body }
func (r *ResponseMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}
func (r *ResponseMessage) From() string               { return "" }
func (r *ResponseMessage) GetParam(key string) string { return "" }
func (r *ResponseMessage) SetMsg(msg *types.RuleMsg)  { r.msg = msg }
func (r *ResponseMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		ruleMsg := types.NewMsg(0, HJ212MsgType, types.JSON, types.NewMetadata(), string(r.body))
		r.msg = &ruleMsg
	}
	return r.msg
}
func (r *ResponseMessage) SetStatusCode(c int) { r.statusCode = c }
func (r *ResponseMessage) SetBody(b []byte)    { r.body = b }
func (r *ResponseMessage) SetError(err error)  { r.err = err }
func (r *ResponseMessage) GetError() error     { return r.err }

// HJ212Config HJ212 endpoint configuration
type HJ212Config struct {
// Listen address, default 0.0.0.0:8005
	Server string `json:"server" label:"Server" desc:"listen address, e.g. 0.0.0.0:8005" required:"true" ref:"primary"`
}

// HJ212Endpoint HJ212 passive receiver endpoint
type HJ212Endpoint struct {
	impl.BaseEndpoint
// GracefulShutdown graceful shutdown
	base.GracefulShutdown
	RuleConfig types.Config
	Config     HJ212Config
// Router (single router, reported data has no path distinction)
	Router   endpointApi.Router
	listener net.Listener
	connCtx  context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

// Type component type
func (x *HJ212Endpoint) Type() string { return Type }

// New creates component instance
func (x *HJ212Endpoint) New() types.Node {
	return &HJ212Endpoint{
		Config: HJ212Config{
			Server: "0.0.0.0:8005",
		},
	}
}

// Init initializes
func (x *HJ212Endpoint) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	x.GracefulShutdown.InitGracefulShutdown(x.RuleConfig.Logger, 10*time.Second)
	x.connCtx, x.cancel = context.WithCancel(context.Background())
	x.conns = make(map[net.Conn]struct{})
	return err
}

// Destroy destroys
func (x *HJ212Endpoint) Destroy() {
	x.GracefulShutdown.GracefulStop(func() {
		_ = x.Close()
	})
}

// Desc component description
func (x *HJ212Endpoint) Desc() string {
	return "HJ212 receiver endpoint. Listens on TCP port for pollution source monitoring devices to report data (HJ 212-2017)"
}

// Category component category
func (x *HJ212Endpoint) Category() string { return "endpoint" }

// Def component definition
func (x *HJ212Endpoint) Def() types.ComponentForm {
	return types.ComponentForm{
		Desc: "HJ212 receiver endpoint. Listens on TCP port for pollution source monitoring devices to report data (HJ 212-2017)",
		RouterForm: &types.RouterForm{
			Hide: true,
		},
	}
}

// Close closes listener
func (x *HJ212Endpoint) Close() error {
	if x.cancel != nil {
		x.cancel()
	}
	if x.listener != nil {
		_ = x.listener.Close()
	}
	// Close active connections to unblock handleConn's blocking conn.Read.
	x.mu.Lock()
	for c := range x.conns {
		_ = c.Close()
	}
	x.mu.Unlock()
	x.wg.Wait()
	return nil
}

// Id returns endpoint ID
func (x *HJ212Endpoint) Id() string { return x.Config.Server }

// AddRouter adds router (single router, reported data has no path distinction)
func (x *HJ212Endpoint) AddRouter(router endpointApi.Router, params ...interface{}) (string, error) {
	if router == nil {
		return "", errors.New("router cannot be nil")
	}
	if x.Router != nil {
		return "", errors.New("hj212 endpoint only supports one router")
	}
	if len(params) > 0 {
		router.SetParams(params...)
	}
	x.CheckAndSetRouterId(router)
	x.Router = router
	return router.GetId(), nil
}

// RemoveRouter removes router
func (x *HJ212Endpoint) RemoveRouter(routerId string, params ...interface{}) error {
	x.Router = nil
	return nil
}

// Start starts TCP listening
func (x *HJ212Endpoint) Start() error {
	listener, err := net.Listen("tcp", x.Config.Server)
	if err != nil {
		return err
	}
	x.listener = listener
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			x.wg.Add(1)
			go func() {
				defer x.wg.Done()
				x.handleConn(conn)
			}()
		}
	}()
	return nil
}

// handleConn reads connection stream, splits frames by ##+length boundary and parses
func (x *HJ212Endpoint) handleConn(conn net.Conn) {
	defer conn.Close()
	x.mu.Lock()
	x.conns[conn] = struct{}{}
	x.mu.Unlock()
	defer func() {
		x.mu.Lock()
		delete(x.conns, conn)
		x.mu.Unlock()
	}()
	x.GracefulShutdown.IncrementActiveOperations()
	defer x.GracefulShutdown.DecrementActiveOperations()
	addr := conn.RemoteAddr().String()
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 1024)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxDataLen+12 { // Overflow protection: discard buffer
				x.Printf("hj212: buffer overflow from %s, drop connection data", addr)
				buf = buf[:0]
			}
			for {
				frame, used, ok := extractFrame(buf)
				if used > 0 && !ok {
					buf = buf[used:]
					continue
				}
				if !ok {
					break
				}
				x.handleFrame(conn, addr, frame)
				buf = buf[used:]
			}
		}
		if err != nil {
			return
		}
	}
}

// handleFrame parses one frame, writes ACK when Flag bit0=1, converts point list to message and flows into rule chain
func (x *HJ212Endpoint) handleFrame(conn net.Conn, from string, raw []byte) {
	frame, err := ParseFrame(raw)
	if err != nil {
		x.Printf("hj212 parse error from %s: %v", from, err)
		return
	}
// Flag bit0=1 means device requires response, immediately write ACK frame
	if flagVal, ferr := strconv.Atoi(frame.Flag); ferr == nil && flagVal&0x01 != 0 {
		ack := BuildAckFrame(frame)
		if _, werr := conn.Write(ack); werr != nil {
			x.Printf("hj212 write ack to %s error: %v", from, werr)
		}
	}
	if x.Router == nil {
		return
	}
	b, err := json.Marshal(frame.Points)
	if err != nil {
		x.Printf("hj212 marshal points error: %v", err)
		return
	}
	exchange := &endpointApi.Exchange{
		In:  &RequestMessage{from: from, body: b},
		Out: &ResponseMessage{},
	}
	md := exchange.In.GetMsg().Metadata
	md.PutValue(MetadataKeyFrom, from)
	md.PutValue(MetadataKeyMN, frame.MN)
	md.PutValue(MetadataKeyST, frame.ST)
	md.PutValue(MetadataKeyCN, frame.CN)
	if !frame.DataTime.IsZero() {
		md.PutValue(MetadataKeyDataTime, frame.DataTime.Format("2006-01-02 15:04:05"))
	}
	x.DoProcess(x.connCtx, x.Router, exchange)
}

// Printf logs
func (x *HJ212Endpoint) Printf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Printf(format, v...)
	}
}
