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

package s7

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robinson/gos7"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// TestS7Nodes 节点类型与默认配置
func TestS7Nodes(t *testing.T) {
	r := &ReadNode{}
	assert.Equal(t, "x/s7Read", r.Type())
	assert.NotNil(t, r.New())

	w := &WriteNode{}
	assert.Equal(t, "x/s7Write", w.Type())
	assert.NotNil(t, w.New())

	rn := r.New().(*ReadNode)
	assert.Equal(t, "127.0.0.1:102", rn.Config.Server)
	assert.Equal(t, 1, rn.Config.Slot)
}

// TestParseAddr 统一 Point.Addr 解析为 S7 寻址（西门子官方语法）。
func TestParseAddr(t *testing.T) {
	// DB 双字
	area, db, addr, bit, isBit, err := parseAddr("DB1.DBD0")
	assert.Nil(t, err)
	assert.Equal(t, "DB", area)
	assert.Equal(t, 1, db)
	assert.Equal(t, 0, addr)
	assert.False(t, isBit)

	// DB 位
	_, _, _, bit, isBit, err = parseAddr("DB1.DBX0.1")
	assert.Nil(t, err)
	assert.Equal(t, 1, bit)
	assert.True(t, isBit)

	// M 字
	area, _, addr, _, isBit, err = parseAddr("MW10")
	assert.Nil(t, err)
	assert.Equal(t, "M", area)
	assert.Equal(t, 10, addr)
	assert.False(t, isBit)

	// M 位简写
	_, _, _, bit, isBit, _ = parseAddr("M0.5")
	assert.Equal(t, 5, bit)
	assert.True(t, isBit)

	// I/Q
	area, _, _, _, _, _ = parseAddr("IW0")
	assert.Equal(t, "I", area)
	area, _, _, _, _, _ = parseAddr("Q0.3")
	assert.Equal(t, "Q", area)

	// % 前缀
	area, _, _, _, _, _ = parseAddr("%M0.1")
	assert.Equal(t, "M", area)

	// 非法
	_, _, _, _, _, err = parseAddr("")
	assert.NotNil(t, err)
	_, _, _, _, _, err = parseAddr("X0")
	assert.NotNil(t, err)
	_, _, _, _, _, err = parseAddr("DB1") // 缺 DBT
	assert.NotNil(t, err)
}

// TestMapType 统一类型 -> S7 原生类型。
func TestMapType(t *testing.T) {
	assert.Equal(t, "INT", mapType("INT16"))
	assert.Equal(t, "WORD", mapType("UINT16"))
	assert.Equal(t, "REAL", mapType("FLOAT32"))
	assert.Equal(t, "LREAL", mapType("FLOAT64"))
	assert.Equal(t, "BOOL", mapType("BOOL"))
	assert.Equal(t, "CUSTOM", mapType("CUSTOM")) // 未知透传
}

// TestS7ReadFailureNoPLC 无 PLC 时连接失败，节点走 Failure 链。
func TestS7ReadFailureNoPLC(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&ReadNode{})
	node, err := test.CreateAndInitNode("x/s7Read", types.Configuration{
		"server":  "127.0.0.1:19999",
		"rack":    0,
		"slot":    1,
		"timeout": 2,
		"points": []map[string]interface{}{
			{"name": "温度", "addr": "DB1.DBD0", "type": "FLOAT32"},
		},
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     `{}`,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		if err == nil {
			t.Fatal("should have connection error for unreachable PLC")
		}
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for s7 read callback")
	}
}

// TestS7WriteFailureNoPLC s7Write 无 PLC 同样走 Failure
func TestS7WriteFailureNoPLC(t *testing.T) {
	registry := &types.SafeComponentSlice{}
	registry.Add(&WriteNode{})
	node, err := test.CreateAndInitNode("x/s7Write", types.Configuration{
		"server":  "127.0.0.1:19999",
		"rack":    0,
		"slot":    1,
		"timeout": 2,
	}, registry)
	assert.Nil(t, err)

	done := make(chan struct{}, 1)
	writePayload := `[{"name":"t","addr":"DB1.DBD0","type":"FLOAT32","value":"1.0"}]`
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: types.JSON,
		MsgType:  "TEST",
		Data:     writePayload,
	}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.NotNil(t, err)
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for s7 write callback")
	}
}

// TestS7OpLockSerializes 验证同一 handler 指针的并发操作被串行化（并发度永不超过 1）。
// 这是同链 ref:// 共享连接安全的基石：gos7 单连接非并发安全，必须串行收发。
// 配合 `go test -race` 可进一步捕获未加锁路径的数据竞争。
func TestS7OpLockSerializes(t *testing.T) {
	ptr := &gos7.TCPClientHandler{}
	var cur int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu := s7OpLocks.Lock(ptr)
			mu.Lock()
			// 临界区内并发度必须 <=1；无锁时拉宽的 sleep 会必现重叠
			if atomic.AddInt32(&cur, 1) > 1 {
				t.Errorf("共享 handler 并发度 > 1（锁未生效）")
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&cur, -1)
			mu.Unlock()
		}()
	}
	wg.Wait()
}

// TestS7OpLockDelete 验证重连后 Delete 清理旧连接的锁条目（无累积泄漏），
// 且不同 handler 指针映射到独立锁（不同连接可并行）。
func TestS7OpLockDelete(t *testing.T) {
	ptr := &gos7.TCPClientHandler{}
	mu1 := s7OpLocks.Lock(ptr)
	s7OpLocks.Delete(ptr)
	mu2 := s7OpLocks.Lock(ptr)
	if mu1 == mu2 {
		t.Fatal("Delete 后应创建新锁，却返回同一 mutex（清理未生效）")
	}
	// 不同 handler 指针互不影响
	if s7OpLocks.Lock(&gos7.TCPClientHandler{}) == mu2 {
		t.Fatal("不同 handler 指针应映射到不同 mutex")
	}
}
