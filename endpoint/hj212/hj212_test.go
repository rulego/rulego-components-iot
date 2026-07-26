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

package hj212

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/test/assert"
)

// buildTestFrame 按 HJ212 格式组帧（自动算长度与 CRC）
func buildTestFrame(seg string) []byte {
	return []byte(fmt.Sprintf("##%04d%s%04X\r\n", len(seg), seg, crc16(seg)))
}

// ------------------------------------------------------------------------------------------------
// 纯函数测试
// ------------------------------------------------------------------------------------------------

// TestCrc16 标准 CRC-16/MODBUS 测试向量（HJ 212-2017 附录A 算法）
func TestCrc16(t *testing.T) {
	assert.Equal(t, uint16(0x4B37), crc16("123456789"))
}

// TestParseFramePollutionSource 污染源实时数据帧（ST=32/CN=2011，Rtd 后缀）
func TestParseFramePollutionSource(t *testing.T) {
	seg := "QN=20170818122101000;ST=32;CN=2011;PW=123456;MN=DEVICE001;Flag=5;" +
		"CP=&&DataTime=20170818122101;a34004-Rtd=2.3,a34004-Flag=N;a34002-Rtd=167.5,a34002-Flag=N;B01-Rtd=1.28&&"
	f, err := ParseFrame(buildTestFrame(seg))
	assert.Nil(t, err)
	assert.Equal(t, "32", f.ST)
	assert.Equal(t, "2011", f.CN)
	assert.Equal(t, "DEVICE001", f.MN)
	assert.Equal(t, "20170818122101000", f.QN)
	assert.Equal(t, "20170818122101", f.DataTime.Format("20060102150405"))

	wantTs := time.Date(2017, 8, 18, 12, 21, 1, 0, time.Local).UnixNano()
	assert.Equal(t, 3, len(f.Points))
	assert.Equal(t, iot_points.Data{Name: "a34004", Value: 2.3, Timestamp: wantTs}, f.Points[0])
	assert.Equal(t, iot_points.Data{Name: "a34002", Value: 167.5, Timestamp: wantTs}, f.Points[1])
	assert.Equal(t, iot_points.Data{Name: "B01", Value: 1.28, Timestamp: wantTs}, f.Points[2])
}

// TestParseFrameMinuteData 分钟数据帧（CN=2051，Avg/Min/Max/Cou 后缀）
func TestParseFrameMinuteData(t *testing.T) {
	seg := "QN=20170818122101000;ST=32;CN=2051;PW=123456;MN=DEVICE001;Flag=4;" +
		"CP=&&DataTime=20170818122000;a34004-Avg=2.1,a34004-Min=1.8,a34004-Max=2.5,a34004-Cou=10.5,a34004-Flag=N&&"
	f, err := ParseFrame(buildTestFrame(seg))
	assert.Nil(t, err)
	assert.Equal(t, "2051", f.CN)
	assert.Equal(t, 4, len(f.Points)) // Flag 非数值后缀不输出
	names := []string{f.Points[0].Name, f.Points[1].Name, f.Points[2].Name, f.Points[3].Name}
	assert.Equal(t, []string{"a34004-Avg", "a34004-Min", "a34004-Max", "a34004-Cou"}, names)
	values := []interface{}{f.Points[0].Value, f.Points[1].Value, f.Points[2].Value, f.Points[3].Value}
	assert.Equal(t, []interface{}{2.1, 1.8, 2.5, 10.5}, values)
}

// TestParseFrameNoDataTime 无 DataTime：Timestamp 为 0
func TestParseFrameNoDataTime(t *testing.T) {
	seg := "QN=20170818122101000;ST=32;CN=2011;PW=123456;MN=DEVICE001;Flag=5;" +
		"CP=&&a34004-Rtd=2.3&&"
	f, err := ParseFrame(buildTestFrame(seg))
	assert.Nil(t, err)
	assert.True(t, f.DataTime.IsZero())
	assert.Equal(t, 1, len(f.Points))
	assert.Equal(t, int64(0), f.Points[0].Timestamp)
}

// TestParseFrameBadCrc CRC 校验失败
func TestParseFrameBadCrc(t *testing.T) {
	seg := "QN=20170818122101000;ST=32;CN=2011;PW=123456;MN=DEVICE001;Flag=5;" +
		"CP=&&DataTime=20170818122101;a34004-Rtd=2.3&&"
	frame := buildTestFrame(seg)
	frame[len(frame)-5] = '0' // 篡改 CRC 一位
	_, err := ParseFrame(frame)
	assert.NotNil(t, err)
}

// TestParseFrameMalformed 非法帧：缺 CP / 长度不符 / 无 ## 前缀
func TestParseFrameMalformed(t *testing.T) {
	// 缺 CP
	seg := "QN=20170818122101000;ST=32;CN=2011;PW=123456;MN=DEVICE001;Flag=5;"
	_, err := ParseFrame(buildTestFrame(seg))
	assert.NotNil(t, err)

	// 长度字段与实际不符
	frame := []byte("##9999ST=32;CN=2011;CP=&&a34004-Rtd=2.3&&0000\r\n")
	_, err = ParseFrame(frame)
	assert.NotNil(t, err)

	// 无 ## 前缀
	_, err = ParseFrame([]byte("ST=32;CN=2011;CP=&&a34004-Rtd=2.3&&\r\n"))
	assert.NotNil(t, err)
}

// TestExtractFrame 流式切帧：前导垃圾跳过、连续两帧、不完整帧等待
func TestExtractFrame(t *testing.T) {
	seg1 := "QN=20170818122101000;ST=32;CN=2011;PW=123456;MN=D1;Flag=5;CP=&&a34004-Rtd=1.1&&"
	seg2 := "QN=20170818122201000;ST=32;CN=2011;PW=123456;MN=D2;Flag=5;CP=&&a34004-Rtd=2.2&&"
	f1 := buildTestFrame(seg1)
	f2 := buildTestFrame(seg2)

	// 前导垃圾 + 完整帧
	buf := append([]byte("garbage##noise"), f1...)
	_, used, ok := extractFrame(buf)
	assert.False(t, ok)
	assert.Equal(t, len("garbage"), used) // 跳过首个 ## 前的垃圾（到第一个 ## 处）
	// 实际 "garbage##noise" 中 ## 在 index 7，used=7；丢弃后 buf 以 ##noise... 开头但长度非法再跳
	buf = buf[used:]
	for {
		frame, used, ok := extractFrame(buf)
		if used > 0 && !ok {
			buf = buf[used:]
			continue
		}
		if !ok {
			break
		}
		parsed, err := ParseFrame(frame)
		assert.Nil(t, err)
		assert.Equal(t, "D1", parsed.MN)
		buf = buf[used:]
	}

	// 连续两帧
	buf = append(append([]byte{}, f1...), f2...)
	var mns []string
	for {
		frame, used, ok := extractFrame(buf)
		if !ok {
			break
		}
		parsed, err := ParseFrame(frame)
		assert.Nil(t, err)
		mns = append(mns, parsed.MN)
		buf = buf[used:]
	}
	assert.Equal(t, []string{"D1", "D2"}, mns)

	// 不完整帧：返回 used=0，等待更多数据
	_, used, ok = extractFrame(f1[:10])
	assert.False(t, ok)
	assert.Equal(t, 0, used)
}

// ------------------------------------------------------------------------------------------------
// 端点元信息测试
// ------------------------------------------------------------------------------------------------

// TestHJ212EndpointMeta 端点类型/默认配置/ID
func TestHJ212EndpointMeta(t *testing.T) {
	ep := &HJ212Endpoint{}
	assert.Equal(t, "endpoint/hj212", ep.Type())
	assert.Equal(t, "endpoint", ep.Category())

	def := ep.New().(*HJ212Endpoint)
	assert.Equal(t, "0.0.0.0:8005", def.Config.Server)
	assert.Equal(t, "0.0.0.0:8005", def.Id())
}

// ------------------------------------------------------------------------------------------------
// 端到端集成测试：endpoint 收设备上报帧
// ------------------------------------------------------------------------------------------------

// TestHJ212EndpointReceive 端到端：endpoint 监听，模拟设备发帧，验证消息数据与 metadata。
func TestHJ212EndpointReceive(t *testing.T) {
	const listenAddr = "127.0.0.1:18212"
	config := rulego.NewConfig(types.WithDefaultPool())

	ep := (&HJ212Endpoint{}).New().(*HJ212Endpoint)
	err := ep.Init(config, types.Configuration{"server": listenAddr})
	assert.Nil(t, err)

	var (
		gotData string
		gotMN   string
		gotST   string
		gotCN   string
		gotDT   string
		mu      sync.Mutex
		wg      sync.WaitGroup
	)
	wg.Add(1)
	ep.AddInterceptors(func(router endpointApi.Router, exchange *endpointApi.Exchange) bool {
		msg := exchange.In.GetMsg()
		mu.Lock()
		gotData = msg.GetData()
		gotMN = msg.Metadata.GetValue("mn")
		gotST = msg.Metadata.GetValue("st")
		gotCN = msg.Metadata.GetValue("cn")
		gotDT = msg.Metadata.GetValue("dataTime")
		mu.Unlock()
		wg.Done()
		return true
	})

	_, err = ep.AddRouter(impl.NewRouter())
	assert.Nil(t, err)

	err = ep.Start()
	assert.Nil(t, err)
	defer ep.Destroy()
	time.Sleep(300 * time.Millisecond) // 等监听就绪

	// 模拟设备上报一帧污染源实时数据
	seg := "QN=20170818122101000;ST=32;CN=2011;PW=123456;MN=DEVICE001;Flag=5;" +
		"CP=&&DataTime=20170818122101;a34004-Rtd=2.3,a34004-Flag=N;a34002-Rtd=167.5,a34002-Flag=N&&"
	conn, err := net.Dial("tcp", listenAddr)
	assert.Nil(t, err)
	_, err = conn.Write(buildTestFrame(seg))
	assert.Nil(t, err)
	_ = conn.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: endpoint did not receive hj212 frame within 3s")
	}

	mu.Lock()
	defer mu.Unlock()
	var points []iot_points.Data
	assert.Nil(t, json.Unmarshal([]byte(gotData), &points))
	assert.Equal(t, 2, len(points))
	assert.Equal(t, "a34004", points[0].Name)
	assert.Equal(t, 2.3, points[0].Value)
	assert.True(t, points[0].Timestamp > 0)
	assert.Equal(t, "a34002", points[1].Name)
	assert.Equal(t, 167.5, points[1].Value)

	assert.Equal(t, "DEVICE001", gotMN)
	assert.Equal(t, "32", gotST)
	assert.Equal(t, "2011", gotCN)
	assert.True(t, strings.Contains(gotDT, "2017-08-18"))
	t.Logf("received hj212 payload: %s", gotData)
}
