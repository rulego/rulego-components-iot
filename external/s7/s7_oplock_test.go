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
)

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
