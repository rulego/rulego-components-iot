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

// Package iec104client wraps third_party/iec104, providing IEC 60870-5-104 master (control station)
// connection to slave (controlled station) and general interrogation bulk acquisition of
// signals/measurements/counter values.
//
// Acquisition model: master initiates general interrogation (GI), slave sends full data
// via multiple ASDUs, this package caches latest values by information object address (IOA).
// ReadPoints triggers one GI and waits for required IOAs to refresh before returning.

package iec104client

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego-components-iot/third_party/go-iecp5/asdu"
	iec104client "github.com/rulego/rulego-components-iot/third_party/iec104/client"
)

// Point IEC 104 acquisition point
type Point struct {
	Name string `json:"name"` // Point name
	Ioa  uint   `json:"ioa"`  // Information object address (IOA)
	Type string `json:"type"` // Expected type identifier (optional, for info only, e.g. M_ME_NC_1)
}

// Data acquisition result
type Data struct {
	Name      string      `json:"name"`
	Address   uint        `json:"address"` // IOA
	Value     interface{} `json:"value"`
	Type      string      `json:"type"`    // Type identifier, e.g. M_SP_NA_1
	Quality   string      `json:"quality"` // good/bad
	Timestamp time.Time   `json:"timestamp"`
}

// ConfigProp IEC 104 connection configuration interface
type ConfigProp interface {
	GetServer() string  // host:port, default port 2404
	GetCommonAddr() int // Common address (CA), default 1
	GetTimeout() int    // General interrogation wait timeout (seconds), default 5
}

// Holder IEC 104 client configuration holder
type Holder struct {
	Config ConfigProp
	OnLink func(active bool)
}

// DefaultHolder default configuration
func DefaultHolder(c ConfigProp) *Holder {
	return &Holder{Config: c}
}

// entry latest value of single IOA
type entry struct {
	value interface{}
	typ   string
	ts    time.Time
	qds   asdu.QualityDescriptor
}

// Client IEC 104 master client. Implements ASDUCall callback itself, continuously caches slave-sent data.
type Client struct {
	c       *iec104client.Client
	common  uint16
	timeout time.Duration
	active  atomic.Bool // Link active (after STARTDT confirmed)
	onLink  func(bool)  // optional link-state callback forwarded from cs104

	mu       sync.RWMutex
	cache    map[uint]*entry // IOA -> latest value
	giDoneAt time.Time       // Current general interrogation completion (ActTerm) time
}

var _ iec104client.ASDUCall = (*Client)(nil)

// NewClient creates and connects IEC 104 master client
func (h *Holder) NewClient() (*Client, error) {
	if h.Config == nil {
		return nil, errors.New("iec104 config is nil")
	}
	host, port, err := iot_points.ParseServer(h.Config.GetServer(), 2404)
	if err != nil {
		return nil, err
	}
	common := h.Config.GetCommonAddr()
	if common == 0 {
		common = 1
	}
	timeout := h.Config.GetTimeout()
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}

	c := &Client{
		common:  uint16(common),
		timeout: time.Duration(timeout) * time.Second,
		cache:   make(map[uint]*entry),
	}
	settings := iec104client.NewSettings()
	settings.Host = host
	settings.Port = port
	settings.AutoConnect = true
	settings.ReconnectInterval = 10 * time.Second
	settings.Cfg104.ConnectTimeout0 = c.timeout
	settings.LogCfg = &iec104client.LogCfg{Enable: false}

	c.onLink = h.OnLink
	c.c = iec104client.New(settings, c)
	c.c.SetServerActiveHandler(func(*iec104client.Client) { c.active.Store(true); if c.onLink != nil { c.onLink(true) } })
	c.c.SetConnectionLostHandler(func(*iec104client.Client) { c.active.Store(false); if c.onLink != nil { c.onLink(false) } })

	if err := c.c.Connect(); err != nil {
		return nil, err
	}
	return c, nil
}

// IsConnected whether connection is established
func (c *Client) IsConnected() bool {
	return c.c != nil && c.c.IsConnected()
}

// Close closes connection
func (c *Client) Close() error {
	if c.c != nil {
		return c.c.Close()
	}
	return nil
}

// ReadPoints initiates general interrogation and collects points. Non-uploaded points marked quality=bad, all failures return error.
func (c *Client) ReadPoints(points []Point) ([]Data, error) {
	if c.c == nil || !c.c.IsConnected() {
		return nil, errors.New("iec104 client not connected")
	}
	// Wait for link activation (cannot send interrogation before first connection STARTDT confirmed)
	if !c.waitActive() {
		return nil, errors.New("iec104 link not active")
	}

	requested := make(map[uint]bool, len(points))
	for _, p := range points {
		requested[p.Ioa] = true
	}

	giAt := time.Now()
	c.mu.Lock()
	c.giDoneAt = time.Time{} // Reset current round completion flag
	c.mu.Unlock()

	if err := c.c.SendInterrogationCmd(c.common); err != nil {
		return nil, err
	}

	// Wait for required IOAs to refresh or current round GI to complete, timeout as fallback
	deadline := time.Now().Add(c.timeout)
	for !c.ready(requested, giAt) && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}

	return c.collect(points, giAt)
}

// waitActive waits for link activation, max timeout
func (c *Client) waitActive() bool {
	if c.active.Load() {
		return true
	}
	deadline := time.Now().Add(c.timeout)
	for !c.active.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	return c.active.Load()
}

// ready all required IOAs refreshed, or current round GI completed (remaining points won't come again)
func (c *Client) ready(requested map[uint]bool, giAt time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.giDoneAt.IsZero() && !c.giDoneAt.Before(giAt) {
		return true
	}
	for ioa := range requested {
		e, ok := c.cache[ioa]
		if !ok || e.ts.Before(giAt) {
			return false
		}
	}
	return true
}

// collect collects results from cache by points
func (c *Client) collect(points []Point, giAt time.Time) ([]Data, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Data, 0, len(points))
	fail := 0
	for _, p := range points {
		d := Data{Name: p.Name, Address: p.Ioa, Timestamp: time.Now()}
		if e, ok := c.cache[p.Ioa]; ok && !e.ts.Before(giAt) {
			d.Value, d.Type, d.Timestamp = e.value, e.typ, e.ts
			// Map the slave's quality descriptor to good/bad. A value flagged Invalid (acquired
			// incorrectly) or NotTopical (stale/last-update-failed) is reported as bad so downstream
			// can drop or alert on it; Overflow/Substituted/Blocked alone still carry usable data.
			if e.qds&(asdu.QDSInvalid|asdu.QDSNotTopical) != 0 {
				d.Quality = "bad"
				fail++
			} else {
				d.Quality = "good"
			}
		} else {
			d.Quality = "bad"
			fail++
		}
		out = append(out, d)
	}
	if len(points) > 0 && fail == len(points) {
		return out, fmt.Errorf("all %d points no data (interrogation timeout)", fail)
	}
	return out, nil
}

// --- ASDUCall callbacks: parse uploaded ASDU and write to cache --

// OnASDU data upload (signal/measurement/counter, etc.)
func (c *Client) OnASDU(a *asdu.ASDU) error {
	c.store(a)
	return nil
}

// OnRead read setpoint response (same as data upload handling)
func (c *Client) OnRead(a *asdu.ASDU) error {
	c.store(a)
	return nil
}

// OnInterrogation general interrogation confirmation/stop. Activation termination (ActTerm) marks current round completion.
func (c *Client) OnInterrogation(a *asdu.ASDU) error {
	if a.Coa.Cause == asdu.ActivationTerm {
		c.mu.Lock()
		c.giDoneAt = time.Now()
		c.mu.Unlock()
	}
	return nil
}

// OnCounterInterrogation counter interrogation response
func (c *Client) OnCounterInterrogation(*asdu.ASDU) error { return nil }

// OnTestCommand test command response
func (c *Client) OnTestCommand(*asdu.ASDU) error { return nil }

// OnClockSync clock sync response
func (c *Client) OnClockSync(*asdu.ASDU) error { return nil }

// OnResetProcess process reset response
func (c *Client) OnResetProcess(*asdu.ASDU) error { return nil }

// OnDelayAcquisition delayed acquisition response
func (c *Client) OnDelayAcquisition(*asdu.ASDU) error { return nil }

// store parses ASDU information body by type identifier, writes to cache by IOA
func (c *Client) store(a *asdu.ASDU) {
	typ := a.Type.String()
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	put := func(ioa uint, value interface{}, ts time.Time, qds asdu.QualityDescriptor) {
		if ts.IsZero() {
			ts = now
		}
		c.cache[ioa] = &entry{value: value, typ: typ, ts: ts, qds: qds}
	}
	switch iec104client.GetDataType(a.Type) {
	case iec104client.SinglePoint:
		for _, p := range a.GetSinglePoint() {
			put(uint(p.Ioa), p.Value, p.Time, p.Qds)
		}
	case iec104client.DoublePoint:
		for _, p := range a.GetDoublePoint() {
			put(uint(p.Ioa), int(p.Value), p.Time, p.Qds)
		}
	case iec104client.StepPosition:
		for _, p := range a.GetStepPosition() {
			put(uint(p.Ioa), p.Value.Val, p.Time, p.Qds)
		}
	case iec104client.BitString32:
		for _, p := range a.GetBitString32() {
			put(uint(p.Ioa), p.Value, p.Time, p.Qds)
		}
	case iec104client.MeasuredValueNormal:
		for _, p := range a.GetMeasuredValueNormal() {
			put(uint(p.Ioa), p.Value.Float64(), p.Time, p.Qds)
		}
	case iec104client.MeasuredValueScaled:
		for _, p := range a.GetMeasuredValueScaled() {
			put(uint(p.Ioa), int(p.Value), p.Time, p.Qds)
		}
	case iec104client.MeasuredValueFloat:
		for _, p := range a.GetMeasuredValueFloat() {
			put(uint(p.Ioa), float64(p.Value), p.Time, p.Qds)
		}
	case iec104client.IntegratedTotals:
		for _, p := range a.GetIntegratedTotals() {
			// BinaryCounterReadingInfo has no Qds field (integrated totals carry a sequence number
			// instead of a quality descriptor per IEC 60870-5), so treat as good quality.
			put(uint(p.Ioa), int64(p.Value.CounterReading), p.Time, 0)
		}
	}
}

// SendControlCmd sends remote control/command command (direct execution, not select-execute two-step).
// typeId values: asdu.C_SC_NA_1 (single command, value=bool) / asdu.C_DC_NA_1 (double command, value=uint8:1 close/2 open) /
// asdu.C_SE_NB_1 (scaled setpoint, value=int16) / asdu.C_SE_NC_1 (short floating point setpoint, value=float32).
func (c *Client) SendControlCmd(typeId asdu.TypeID, ioa uint, value any) error {
	if c.c == nil || !c.c.IsConnected() {
		return errors.New("iec104 client not connected")
	}
	if !c.waitActive() {
		return errors.New("iec104 link not active")
	}
	return c.c.SendCmd(c.common, typeId, asdu.InfoObjAddr(ioa), value)
}
