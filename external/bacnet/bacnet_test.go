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

package bacnet

import (
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	bacnetclient "github.com/rulego/rulego-components-iot/pkg/bacnet_client"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
)

func TestParsePointAddr(t *testing.T) {
	cases := []struct {
		in       string
		objType  uint16
		instance uint32
		property uint32
	}{
		{"analog-input:0", 0, 0, bacnetclient.PropertyPresentValue},
		{"ai:1:description", 0, 1, bacnetclient.PropertyDescription},
		{"device:100", 8, 100, bacnetclient.PropertyPresentValue},
		{"multistate-value:2:object-name", 19, 2, bacnetclient.PropertyObjectName},
		{"0:5:77", 0, 5, 77},
		{"bi:3", 3, 3, bacnetclient.PropertyPresentValue},
	}
	for _, c := range cases {
		a, err := ParsePointAddr(c.in)
		if err != nil {
			t.Errorf("ParsePointAddr(%q) error: %v", c.in, err)
			continue
		}
		if a.ObjectType != c.objType || a.Instance != c.instance || a.Property != c.property {
			t.Errorf("ParsePointAddr(%q) = %+v, want type=%d inst=%d prop=%d", c.in, a, c.objType, c.instance, c.property)
		}
	}
	if _, err := ParsePointAddr("bad"); err == nil {
		t.Error("expected error for malformed addr")
	}
}

func TestEncodeValue(t *testing.T) {
	cases := []struct {
		typeStr string
		value   string
		tag     uint8
		want    interface{}
	}{
		{"FLOAT32", "1.5", bacnetclient.AppTagReal, float64(1.5)},
		{"", "2.5", bacnetclient.AppTagReal, float64(2.5)},
		{"BOOL", "true", bacnetclient.AppTagBoolean, true},
		{"ENUM", "3", bacnetclient.AppTagEnumerated, uint64(3)},
		{"STRING", "hi", bacnetclient.AppTagCharacterString, "hi"},
		{"INT32", "-5", bacnetclient.AppTagSignedInt, int64(-5)},
		{"UINT16", "7", bacnetclient.AppTagUnsignedInt, uint64(7)},
	}
	for _, c := range cases {
		tag, val, err := encodeValue(c.typeStr, c.value)
		if err != nil {
			t.Errorf("encodeValue(%q,%q) error: %v", c.typeStr, c.value, err)
			continue
		}
		if tag != c.tag || !reflect.DeepEqual(val, c.want) {
			t.Errorf("encodeValue(%q,%q) = (tag=%d, val=%v(%T)), want (tag=%d, val=%v)", c.typeStr, c.value, tag, val, val, c.tag, c.want)
		}
	}
}

func TestDriverReadViaMock(t *testing.T) {
	srv, err := bacnetclient.NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()
	srv.SetRead(bacnetclient.ObjectTypeAnalogInput, 0, bacnetclient.PropertyPresentValue, bacnetclient.AppTagReal, float64(210.0))
	srv.SetRead(bacnetclient.ObjectTypeBinaryInput, 1, bacnetclient.PropertyPresentValue, bacnetclient.AppTagBoolean, true)
	srv.SetRead(bacnetclient.ObjectTypeMultiStateInput, 2, bacnetclient.PropertyPresentValue, bacnetclient.AppTagEnumerated, uint64(3))
	srv.SetError(bacnetclient.ObjectTypeAnalogInput, 9, bacnetclient.PropertyPresentValue)

	c, err := bacnetclient.NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	d := newDriver(c, nil, 0)

	points := []iot_points.Point{
		{Name: "temp", Addr: "analog-input:0", Scale: 0.1}, // 210 * 0.1 = 21.0
		{Name: "fan", Addr: "bi:1"},
		{Name: "mode", Addr: "msi:2"},
		{Name: "bad", Addr: "analog-input:9"}, // single-point error, others unaffected
	}
	data, err := d.ReadPoints(points)
	if err != nil {
		t.Fatalf("ReadPoints error: %v", err)
	}
	if len(data) != 4 {
		t.Fatalf("got %d data, want 4", len(data))
	}
	if data[0].Value != float64(21.0) {
		t.Errorf("temp = %v, want 21.0 (scale applied)", data[0].Value)
	}
	if data[1].Value != true {
		t.Errorf("fan = %v, want true", data[1].Value)
	}
	if data[2].Value != uint64(3) {
		t.Errorf("mode = %v, want 3", data[2].Value)
	}
	if data[3].Error == "" {
		t.Error("bad point should carry an error, got none")
	}
}

// Single point: uses ReadProperty path (not RPM).
func TestDriverReadSinglePoint(t *testing.T) {
	srv, err := bacnetclient.NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()
	srv.SetRead(bacnetclient.ObjectTypeAnalogInput, 0, bacnetclient.PropertyPresentValue, bacnetclient.AppTagReal, float64(21.5))

	c, err := bacnetclient.NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	d := newDriver(c, nil, 0)

	data, err := d.ReadPoints([]iot_points.Point{{Name: "temp", Addr: "analog-input:0", Scale: 0.1}})
	if err != nil {
		t.Fatalf("ReadPoints: %v", err)
	}
	if data[0].Value != 2.15 { // 21.5 * 0.1
		t.Errorf("got %v, want 2.15", data[0].Value)
	}
}

// Multi-point with same object different properties: RPM groups them into one access spec.
func TestDriverReadMultipleObjects(t *testing.T) {
	srv, err := bacnetclient.NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()
	srv.SetRead(bacnetclient.ObjectTypeAnalogInput, 0, bacnetclient.PropertyPresentValue, bacnetclient.AppTagReal, float64(10.0))
	srv.SetRead(bacnetclient.ObjectTypeAnalogInput, 0, bacnetclient.PropertyObjectName, bacnetclient.AppTagCharacterString, "sensor0")
	srv.SetRead(bacnetclient.ObjectTypeBinaryInput, 1, bacnetclient.PropertyPresentValue, bacnetclient.AppTagBoolean, true)
	srv.SetRead(bacnetclient.ObjectTypeMultiStateInput, 2, bacnetclient.PropertyPresentValue, bacnetclient.AppTagEnumerated, uint64(3))

	c, err := bacnetclient.NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	d := newDriver(c, nil, 0)

	points := []iot_points.Point{
		{Name: "temp", Addr: "analog-input:0"},
		{Name: "name", Addr: "analog-input:0:object-name"}, // same object, different property
		{Name: "fan", Addr: "bi:1"},
		{Name: "mode", Addr: "msi:2"},
	}
	data, err := d.ReadPoints(points)
	if err != nil {
		t.Fatalf("ReadPoints: %v", err)
	}
	if len(data) != 4 {
		t.Fatalf("got %d points, want 4", len(data))
	}
	if data[0].Value != float64(10.0) {
		t.Errorf("temp = %v, want 10.0", data[0].Value)
	}
	if data[1].Value != "sensor0" {
		t.Errorf("name = %v, want sensor0", data[1].Value)
	}
	if data[2].Value != true {
		t.Errorf("fan = %v, want true", data[2].Value)
	}
	if data[3].Value != uint64(3) {
		t.Errorf("mode = %v, want 3", data[3].Value)
	}
}

// RPM unsupported by device: driver falls back to per-point ReadProperty.
func TestDriverReadFallback(t *testing.T) {
	srv, err := bacnetclient.NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()
	srv.SetRpmUnsupported() // RPM returns Error
	srv.SetRead(bacnetclient.ObjectTypeAnalogInput, 0, bacnetclient.PropertyPresentValue, bacnetclient.AppTagReal, float64(5.0))
	srv.SetRead(bacnetclient.ObjectTypeBinaryInput, 1, bacnetclient.PropertyPresentValue, bacnetclient.AppTagBoolean, true)

	c, err := bacnetclient.NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	d := newDriver(c, nil, 0)

	points := []iot_points.Point{
		{Name: "temp", Addr: "analog-input:0"},
		{Name: "fan", Addr: "bi:1"},
	}
	data, err := d.ReadPoints(points)
	if err != nil {
		t.Fatalf("ReadPoints (fallback): %v", err)
	}
	if data[0].Value != float64(5.0) {
		t.Errorf("temp = %v, want 5.0 (via fallback ReadProperty)", data[0].Value)
	}
	if data[1].Value != true {
		t.Errorf("fan = %v, want true (via fallback ReadProperty)", data[1].Value)
	}
}

func TestDriverWriteViaMock(t *testing.T) {
	srv, err := bacnetclient.NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()

	c, err := bacnetclient.NewClient(srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	d := newDriver(c, nil, 8)

	points := []iot_points.Point{
		{Name: "setpoint", Addr: "analog-output:0", Type: "FLOAT32", Value: "18.5"},
		{Name: "fan", Addr: "binary-output:1", Type: "BOOL", Value: "true"},
		{Name: "mode", Addr: "multistate-value:2", Type: "ENUM", Value: "2"},
	}
	if err := d.WritePoints(points); err != nil {
		t.Fatalf("WritePoints error: %v", err)
	}
	writes := srv.Writes()
	if got := writes["1:0:85"]; got != float64(18.5) {
		t.Errorf("analog write = %v, want 18.5", got)
	}
	if got := writes["4:1:85"]; got != true {
		t.Errorf("binary write = %v, want true", got)
	}
	if got := writes["19:2:85"]; got != uint64(2) {
		t.Errorf("multistate write = %v, want 2", got)
	}
}

// TestDriverReadTimeoutSkipsFallback: The device is completely unresponsive (the UDP socket swallows requests and never replies),
// RPM times out and returns an error immediately, no longer falling back to point-by-point ReadProperty
// (point-by-point would just wait another full timeout window against the same silence).
func TestDriverReadTimeoutSkipsFallback(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()

	var got int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			if _, _, err := silent.ReadFrom(buf); err != nil {
				return
			}
			atomic.AddInt32(&got, 1)
		}
	}()

	c, err := bacnetclient.NewClient(silent.LocalAddr().String(), 300*time.Millisecond)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	d := newDriver(c, nil, 0)

	pts := []iot_points.Point{
		{Name: "a", Addr: "analog-input:0"},
		{Name: "b", Addr: "analog-input:1"},
		{Name: "c", Addr: "analog-input:2"},
	}
	_, err = d.ReadPoints(pts)
	if err == nil {
		t.Fatal("want timeout error against silent device")
	}
	_ = silent.Close()
	<-done
	if n := atomic.LoadInt32(&got); n != 1 {
		t.Errorf("got %d requests, want 1 (RPM only, no per-point fallback)", n)
	}
}

// TestNodeStatusReporting: 读成功后上报 Connected;对静默设备失败后处于 Reconnecting。
func TestNodeStatusReporting(t *testing.T) {
	srv, err := bacnetclient.NewMockServer()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer srv.Close()
	srv.SetRead(bacnetclient.ObjectTypeAnalogInput, 0, bacnetclient.PropertyPresentValue, bacnetclient.AppTagReal, float64(21.5))

	node := &ReadNode{Config: Configuration{
		Server:  srv.Addr(),
		Timeout: 1,
		Points:  []iot_points.Point{{Name: "t", Addr: "analog-input:0"}},
	}}
	if err := node.SharedNode.InitWithClose(types.NewConfig(), node.Type(), node.Config.Server, false, node.newClient, closeClient); err != nil {
		t.Fatalf("init: %v", err)
	}
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		if relationType != types.Success {
			t.Errorf("want Success, got %s err=%v", relationType, err)
		}
		done <- struct{}{}
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for callback")
	}
	if s := node.SharedNode.ConnectionStatus(); s.Status != types.StatusConnected {
		t.Errorf("after successful read, status = %v, want Connected", s.Status)
	}

	// Point to a silent port, re-Init, verify that after failure it is Reconnecting
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	node2 := &ReadNode{Config: Configuration{
		Server:  silent.LocalAddr().String(),
		Timeout: 1,
		Points:  []iot_points.Point{{Name: "t", Addr: "analog-input:0"}},
	}}
	if err := node2.SharedNode.InitWithClose(types.NewConfig(), node2.Type(), node2.Config.Server, false, node2.newClient, closeClient); err != nil {
		t.Fatalf("init2: %v", err)
	}
	done2 := make(chan struct{}, 1)
	test.NodeOnMsg(t, node2, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		if relationType != types.Failure {
			t.Errorf("want Failure, got %s", relationType)
		}
		done2 <- struct{}{}
	})
	select {
	case <-done2:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for failure callback")
	}
	if s := node2.SharedNode.ConnectionStatus(); s.Status != types.StatusReconnecting {
		t.Errorf("after failed read, status = %v, want Reconnecting", s.Status)
	}
}
