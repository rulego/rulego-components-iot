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

// Package iec104client 封装 wendy512/iec104，提供 IEC 60870-5-104 主站(控制站)
// 连接子站(被控站)、总召唤批量采集遥信/遥测/遥脉的能力。
//
// 采集模型：主站发起总召唤(GI)，子站以多个 ASDU 上送全数据，本包按信息体地址(IOA)
// 缓存最新值。ReadPoints 触发一次总召唤并等待所需 IOA 刷新后返回。
package iec104client

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/wendy512/go-iecp5/asdu"
	iec104client "github.com/wendy512/iec104/client"
)

// Point IEC 104 采集点位
type Point struct {
	Name string `json:"name"` // 点位名称
	Ioa  uint   `json:"ioa"`  // 信息体地址(IOA)
	Type string `json:"type"` // 期望类型标识(可选,仅说明,如 M_ME_NC_1)
}

// Data 采集结果
type Data struct {
	Name      string      `json:"name"`
	Address   uint        `json:"address"` // IOA
	Value     interface{} `json:"value"`
	Type      string      `json:"type"`    // 类型标识,如 M_SP_NA_1
	Quality   string      `json:"quality"` // good/bad
	Timestamp time.Time   `json:"timestamp"`
}

// ConfigProp IEC 104 连接配置接口
type ConfigProp interface {
	GetServer() string  // host:port,默认端口 2404
	GetCommonAddr() int // 公共地址(CA),默认 1
	GetTimeout() int    // 总召唤等待超时(秒),默认 5
}

// Holder IEC 104 客户端配置持有者
type Holder struct {
	Config ConfigProp
}

// DefaultHolder 默认配置
func DefaultHolder(c ConfigProp) *Holder {
	return &Holder{Config: c}
}

// entry 单个 IOA 的最新值
type entry struct {
	value interface{}
	typ   string
	ts    time.Time
}

// Client IEC 104 主站客户端。自身实现 ASDUCall 回调,持续缓存子站上送数据。
type Client struct {
	c       *iec104client.Client
	common  uint16
	timeout time.Duration
	active  atomic.Bool // 链路激活(STARTDT 确认后)

	mu       sync.RWMutex
	cache    map[uint]*entry // IOA -> 最新值
	giDoneAt time.Time       // 本次总召唤完成(ActTerm)时间
}

var _ iec104client.ASDUCall = (*Client)(nil)

// NewClient 创建并连接 IEC 104 主站客户端
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

	c.c = iec104client.New(settings, c)
	c.c.SetServerActiveHandler(func(*iec104client.Client) { c.active.Store(true) })
	c.c.SetConnectionLostHandler(func(*iec104client.Client) { c.active.Store(false) })

	if err := c.c.Connect(); err != nil {
		return nil, err
	}
	return c, nil
}

// IsConnected 连接是否建立
func (c *Client) IsConnected() bool {
	return c.c != nil && c.c.IsConnected()
}

// Close 关闭连接
func (c *Client) Close() error {
	if c.c != nil {
		return c.c.Close()
	}
	return nil
}

// ReadPoints 发起总召唤并采集点位。单点未上送标记 quality=bad,全部失败返回 error。
func (c *Client) ReadPoints(points []Point) ([]Data, error) {
	if c.c == nil || !c.c.IsConnected() {
		return nil, errors.New("iec104 client not connected")
	}
	// 等待链路激活(首次连接 STARTDT 确认前无法发召唤)
	if !c.waitActive() {
		return nil, errors.New("iec104 link not active")
	}

	requested := make(map[uint]bool, len(points))
	for _, p := range points {
		requested[p.Ioa] = true
	}

	giAt := time.Now()
	c.mu.Lock()
	c.giDoneAt = time.Time{} // 重置本轮完成标记
	c.mu.Unlock()

	if err := c.c.SendInterrogationCmd(c.common); err != nil {
		return nil, err
	}

	// 等待所需 IOA 刷新或本轮总召唤完成,超时兜底
	deadline := time.Now().Add(c.timeout)
	for !c.ready(requested, giAt) && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}

	return c.collect(points, giAt)
}

// waitActive 等待链路激活,最多 timeout
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

// ready 所需 IOA 均已刷新,或本轮总召唤已完成(剩余点子上送不会再来)
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

// collect 从缓存按点位收集结果
func (c *Client) collect(points []Point, giAt time.Time) ([]Data, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Data, 0, len(points))
	fail := 0
	for _, p := range points {
		d := Data{Name: p.Name, Address: p.Ioa, Timestamp: time.Now()}
		if e, ok := c.cache[p.Ioa]; ok && !e.ts.Before(giAt) {
			d.Value, d.Type, d.Quality, d.Timestamp = e.value, e.typ, "good", e.ts
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

// --- ASDUCall 回调:解析上送 ASDU 写入缓存 ---

// OnASDU 数据上送(遥信/遥测/遥脉等)
func (c *Client) OnASDU(a *asdu.ASDU) error {
	c.store(a)
	return nil
}

// OnRead 读定值回复(同数据上送处理)
func (c *Client) OnRead(a *asdu.ASDU) error {
	c.store(a)
	return nil
}

// OnInterrogation 总召唤确认/停止。收到激活停止(ActTerm)标记本轮完成。
func (c *Client) OnInterrogation(a *asdu.ASDU) error {
	if a.Coa.Cause == asdu.ActivationTerm {
		c.mu.Lock()
		c.giDoneAt = time.Now()
		c.mu.Unlock()
	}
	return nil
}

// OnCounterInterrogation 累积量召唤回复
func (c *Client) OnCounterInterrogation(*asdu.ASDU) error { return nil }

// OnTestCommand 测试命令回复
func (c *Client) OnTestCommand(*asdu.ASDU) error { return nil }

// OnClockSync 时钟同步回复
func (c *Client) OnClockSync(*asdu.ASDU) error { return nil }

// OnResetProcess 进程重置回复
func (c *Client) OnResetProcess(*asdu.ASDU) error { return nil }

// OnDelayAcquisition 延迟获取回复
func (c *Client) OnDelayAcquisition(*asdu.ASDU) error { return nil }

// store 按类型标识解析 ASDU 信息体,按 IOA 写入缓存
func (c *Client) store(a *asdu.ASDU) {
	typ := a.Type.String()
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	put := func(ioa uint, value interface{}, ts time.Time) {
		if ts.IsZero() {
			ts = now
		}
		c.cache[ioa] = &entry{value: value, typ: typ, ts: ts}
	}
	switch iec104client.GetDataType(a.Type) {
	case iec104client.SinglePoint:
		for _, p := range a.GetSinglePoint() {
			put(uint(p.Ioa), p.Value, p.Time)
		}
	case iec104client.DoublePoint:
		for _, p := range a.GetDoublePoint() {
			put(uint(p.Ioa), int(p.Value), p.Time)
		}
	case iec104client.StepPosition:
		for _, p := range a.GetStepPosition() {
			put(uint(p.Ioa), p.Value.Val, p.Time)
		}
	case iec104client.BitString32:
		for _, p := range a.GetBitString32() {
			put(uint(p.Ioa), p.Value, p.Time)
		}
	case iec104client.MeasuredValueNormal:
		for _, p := range a.GetMeasuredValueNormal() {
			put(uint(p.Ioa), p.Value.Float64(), p.Time)
		}
	case iec104client.MeasuredValueScaled:
		for _, p := range a.GetMeasuredValueScaled() {
			put(uint(p.Ioa), int(p.Value), p.Time)
		}
	case iec104client.MeasuredValueFloat:
		for _, p := range a.GetMeasuredValueFloat() {
			put(uint(p.Ioa), float64(p.Value), p.Time)
		}
	case iec104client.IntegratedTotals:
		for _, p := range a.GetIntegratedTotals() {
			put(uint(p.Ioa), int64(p.Value.CounterReading), p.Time)
		}
	}
}

// SendControlCmd 发送遥控/遥调命令(直接执行,非选择-执行两步)。
// typeId 取值：asdu.C_SC_NA_1(单命令,value=bool) / asdu.C_DC_NA_1(双命令,value=uint8:1合/2分) /
// asdu.C_SE_NB_1(标度化设点,value=int16) / asdu.C_SE_NC_1(短浮点设点,value=float32)。
func (c *Client) SendControlCmd(typeId asdu.TypeID, ioa uint, value any) error {
	if c.c == nil || !c.c.IsConnected() {
		return errors.New("iec104 client not connected")
	}
	if !c.waitActive() {
		return errors.New("iec104 link not active")
	}
	return c.c.SendCmd(c.common, typeId, asdu.InfoObjAddr(ioa), value)
}
