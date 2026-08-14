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

package iot_points

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
)

// fakeSharedConn 记录状态变化并持有一个可替换的 client。
type fakeSharedConn struct {
	mu       sync.Mutex
	client   *fakeConn
	statuses []types.NodeStatus
	getErr   error
}

func (f *fakeSharedConn) GetSafely() (*fakeConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.client, nil
}

func (f *fakeSharedConn) SetStatus(s types.NodeStatus, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, s)
}

func (f *fakeSharedConn) lastStatus() types.NodeStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statuses) == 0 {
		return types.NodeStatus(0)
	}
	return f.statuses[len(f.statuses)-1]
}

func (f *fakeSharedConn) swap(c *fakeConn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.client = c
}

// fakeConn 记录读取次数,按脚本返回结果。
type fakeConn struct {
	id     int
	script func(call int) ([]Data, error)
	calls  int
}

func (c *fakeConn) read() ([]Data, error) {
	c.calls++
	return c.script(c.calls)
}

// runnerNode 把 RunRead 包成 types.Node 以便用 test.NodeOnMsg 驱动。
type runnerNode struct {
	shared *fakeSharedConn
	opts   func() RunOpts[*fakeConn]
}

func (n *runnerNode) New() types.Node                              { return n }
func (n *runnerNode) Type() string                                 { return "test/runner" }
func (n *runnerNode) Init(types.Config, types.Configuration) error { return nil }
func (n *runnerNode) Destroy()                                     {}

func (n *runnerNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	RunRead(ctx, msg, func(c *fakeConn) ([]Data, error) { return c.read() }, n.opts())
}

// writeRunnerNode 同上,驱动 RunWrite。
type writeRunnerNode struct {
	runnerNode
}

func (n *writeRunnerNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	RunWrite(ctx, msg, func(c *fakeConn) error {
		_, err := c.read()
		return err
	}, n.opts())
}

func newRunnerEnv(script func(call int) ([]Data, error)) (*runnerNode, *fakeSharedConn, *fakeConn, *OpLocks) {
	conn := &fakeConn{id: 1, script: script}
	shared := &fakeSharedConn{client: conn}
	locks := &OpLocks{}
	node := &runnerNode{
		shared: shared,
		opts: func() RunOpts[*fakeConn] {
			return RunOpts[*fakeConn]{
				Shared: shared,
				Reconnect: func(old *fakeConn, attempt int) (*fakeConn, error) {
					nc := &fakeConn{id: old.id + 1, script: script}
					shared.swap(nc)
					return nc, nil
				},
				OpLocks: locks,
				Prefix:  "[TEST]",
			}
		},
	}
	return node, shared, conn, locks
}

// 成功路径:一次读通,Success + 数据回填 + 状态 Connected。
func TestRunRead_Success(t *testing.T) {
	node, shared, conn, _ := newRunnerEnv(func(call int) ([]Data, error) {
		return []Data{{Name: "t1", Value: 42}}, nil
	})
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Success, relationType)
		assert.Nil(t, err)
		assert.True(t, strings.Contains(msg.GetData(), `"t1"`), "数据应回填 msg: %s", msg.GetData())
		done <- struct{}{}
	})
	waitDone(t, done)
	assert.Equal(t, 1, conn.calls)
	assert.Equal(t, types.StatusConnected, shared.lastStatus())
}

// 失败一次→重连→成功:RebuildConn 语义(换 client),最终 Success。
func TestRunRead_ReconnectThenSuccess(t *testing.T) {
	var total int32
	script := func(call int) ([]Data, error) {
		if atomic.AddInt32(&total, 1) == 1 {
			return nil, errors.New("connection reset")
		}
		return []Data{{Name: "t1", Value: 1}}, nil
	}
	node, shared, old, locks := newRunnerEnv(script)
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Success, relationType)
		done <- struct{}{}
	})
	waitDone(t, done)
	assert.Equal(t, 1, old.calls, "旧 client 只应被读过一次")
	assert.False(t, locks.Has(old), "重连后旧 client 的锁应被删除")
	assert.Equal(t, types.StatusConnected, shared.lastStatus())
}

// 重试耗尽:DefaultMaxRetries+1 次尝试后 Failure,错误为最后一次。
func TestRunRead_Exhaustion(t *testing.T) {
	wantErr := errors.New("connection refused")
	var total int32
	node, _, _, _ := newRunnerEnv(func(call int) ([]Data, error) {
		atomic.AddInt32(&total, 1)
		return nil, wantErr
	})
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		assert.True(t, errors.Is(err, wantErr))
		done <- struct{}{}
	})
	waitDone(t, done)
	assert.Equal(t, int32(DefaultMaxRetries+1), atomic.LoadInt32(&total), "应尝试 DefaultMaxRetries+1 次")
}

// UDP 语义(RetryOnTimeout=false):超时直接失败,不重连。
func TestRunRead_TimeoutFailFast(t *testing.T) {
	var total int32
	node, shared, _, _ := newRunnerEnv(func(call int) ([]Data, error) {
		atomic.AddInt32(&total, 1)
		return nil, errors.New("request timeout (after 0 retries)")
	})
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		assert.True(t, strings.Contains(err.Error(), "timeout"))
		done <- struct{}{}
	})
	waitDone(t, done)
	assert.Equal(t, int32(1), atomic.LoadInt32(&total), "超时应只尝试一次")
	assert.Equal(t, types.StatusReconnecting, shared.lastStatus(), "失败也要反映到状态")
}

// TCP 语义(RetryOnTimeout=true):超时也重试到耗尽。
func TestRunRead_TimeoutRetried(t *testing.T) {
	var total int32
	node, shared, _, _ := newRunnerEnv(func(call int) ([]Data, error) {
		atomic.AddInt32(&total, 1)
		return nil, errors.New("i/o timeout")
	})
	orig := node.opts
	node.opts = func() RunOpts[*fakeConn] {
		o := orig()
		o.RetryOnTimeout = true
		return o
	}
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})
	waitDone(t, done)
	assert.Equal(t, int32(DefaultMaxRetries+1), atomic.LoadInt32(&total), "RetryOnTimeout 应重试到耗尽")
	assert.Equal(t, types.StatusReconnecting, shared.lastStatus())
}

// 重连本身失败:立即 Failure,带重连错误。
func TestRunRead_ReconnectError(t *testing.T) {
	node, _, _, _ := newRunnerEnv(func(call int) ([]Data, error) {
		return nil, errors.New("broken pipe")
	})
	orig := node.opts
	reconnErr := errors.New("dial failed")
	node.opts = func() RunOpts[*fakeConn] {
		o := orig()
		o.Reconnect = func(old *fakeConn, attempt int) (*fakeConn, error) { return nil, reconnErr }
		return o
	}
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		assert.True(t, errors.Is(err, reconnErr))
		done <- struct{}{}
	})
	waitDone(t, done)
}

// GetSafely 失败:直接 Failure。
func TestRunRead_GetClientError(t *testing.T) {
	node, shared, _, _ := newRunnerEnv(func(call int) ([]Data, error) { return nil, nil })
	shared.getErr = errors.New("not init")
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		done <- struct{}{}
	})
	waitDone(t, done)
}

// LockWait 有界等待:锁被占有时快速失败而不是无限排队。
func TestRunRead_BusyFailFast(t *testing.T) {
	conn := &fakeConn{script: func(int) ([]Data, error) { return []Data{{Name: "ok"}}, nil }}
	shared := &fakeSharedConn{client: conn}
	locks := &OpLocks{}
	rel, _ := locks.TryLockTimeout(any(conn), 0) // 模拟上一笔操作还持锁
	n := &runnerNode{shared: shared}
	n.opts = func() RunOpts[*fakeConn] {
		return RunOpts[*fakeConn]{
			Shared:    shared,
			Reconnect: func(old *fakeConn, attempt int) (*fakeConn, error) { return old, nil },
			OpLocks:   locks,
			LockWait:  20 * time.Millisecond,
			Prefix:    "[TEST]",
		}
	}
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, n, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Failure, relationType)
		assert.True(t, strings.Contains(err.Error(), "busy"), "应是 busy 错误: %v", err)
		done <- struct{}{}
	})
	waitDone(t, done)
	assert.Equal(t, 0, conn.calls, "busy 时不应执行读")
	rel()
}

// 写路径:成功 TellSuccess 且不改写数据;失败走同一重试骨架。
func TestRunWrite_SuccessAndFailure(t *testing.T) {
	var total int32
	script := func(call int) ([]Data, error) {
		if atomic.AddInt32(&total, 1) == 1 {
			return nil, errors.New("connection reset")
		}
		return nil, nil
	}
	env, _, _, _ := newRunnerEnv(script)
	node := &writeRunnerNode{runnerNode: *env}
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{Data: `{"v":1}`}}, func(msg types.RuleMsg, relationType string, err error) {
		assert.Equal(t, types.Success, relationType)
		assert.Nil(t, err)
		done <- struct{}{}
	})
	waitDone(t, done)
}

// 并发串行:同一 client 的读回调不重叠。
func TestRunRead_ConcurrentSerialized(t *testing.T) {
	var inside, maxInside int32
	conn := &fakeConn{script: func(call int) ([]Data, error) {
		cur := atomic.AddInt32(&inside, 1)
		for {
			old := atomic.LoadInt32(&maxInside)
			if cur <= old || atomic.CompareAndSwapInt32(&maxInside, old, cur) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt32(&inside, -1)
		return []Data{{Name: "x"}}, nil
	}}
	shared := &fakeSharedConn{client: conn}
	locks := &OpLocks{}
	node := &runnerNode{shared: shared}
	node.opts = func() RunOpts[*fakeConn] {
		return RunOpts[*fakeConn]{
			Shared:    shared,
			Reconnect: func(old *fakeConn, attempt int) (*fakeConn, error) { return old, nil },
			OpLocks:   locks,
			Prefix:    "[TEST]",
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			test.NodeOnMsg(t, node, []test.Msg{{Data: `{}`}}, func(msg types.RuleMsg, relationType string, err error) {
				assert.Equal(t, types.Success, relationType)
			})
		}()
	}
	wg.Wait()
	assert.True(t, atomic.LoadInt32(&maxInside) == 1, "读回调出现并发: %d", maxInside)
}

// RebuildConn:他人已重连(current != old)时直接返回新 client,不重复关闭。
func TestRebuildConn_AlreadyReplaced(t *testing.T) {
	old := &fakeConn{}
	fresh := &fakeConn{}
	get := func() (*fakeConn, error) { return fresh, nil }
	closed := false
	c, err := RebuildConn(&sync.Mutex{}, get, func(*fakeConn) {}, old, 0,
		func() (*fakeConn, error) { t.Fatal("不应新建"); return nil, nil },
		func(*fakeConn) error { closed = true; return nil })
	assert.Nil(t, err)
	assert.True(t, c == fresh)
	assert.False(t, closed, "他人已重连时不应关闭")
}

// RebuildConn:正常路径关旧→退避→新建→Refresh。
func TestRebuildConn_Rebuild(t *testing.T) {
	old := &fakeConn{}
	var current *fakeConn = old
	closed := false
	refreshed := false
	c, err := RebuildConn(&sync.Mutex{},
		func() (*fakeConn, error) { return current, nil },
		func(c *fakeConn) { refreshed = true; current = c },
		old, 0,
		func() (*fakeConn, error) { return &fakeConn{}, nil },
		func(*fakeConn) error { closed = true; return nil })
	assert.Nil(t, err)
	assert.NotNil(t, c)
	assert.True(t, closed)
	assert.True(t, refreshed)
}

func waitDone(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for callback")
	}
}

// fakePoolNodeCtx 只覆盖 GetNode,其余接口方法经嵌入满足(不会被调用)。
type fakePoolNodeCtx struct {
	types.SharedNodeCtx
	node interface{}
}

func (f *fakePoolNodeCtx) GetNode() interface{} { return f.node }

type fakePool struct {
	types.NodePool
	ctx map[string]types.SharedNodeCtx
}

func (f *fakePool) Get(id string) (types.SharedNodeCtx, bool) {
	c, ok := f.ctx[id]
	return c, ok
}

// ownerNode 实现 ReconnectNode[*fakeConn]。
type ownerNode struct {
	calls int
}

func (o *ownerNode) ReconnectNode(old *fakeConn, attempt int) (*fakeConn, error) {
	o.calls++
	return &fakeConn{}, nil
}

// TestBorrowerReconnect: ref:// 借用方委托池内 owner;找不到 owner 时报错。
func TestBorrowerReconnect(t *testing.T) {
	owner := &ownerNode{}
	pool := &fakePool{ctx: map[string]types.SharedNodeCtx{"node1": &fakePoolNodeCtx{node: owner}}}

	got, err := BorrowerReconnect[*fakeConn](pool, "node1", "test", &fakeConn{}, 0)
	assert.Nil(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, 1, owner.calls, "应委托到 owner 的 ReconnectNode")

	_, err = BorrowerReconnect[*fakeConn](pool, "missing", "test", &fakeConn{}, 0)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "borrower does not own"), "错误应说明借用方不拥有连接: %v", err)

	// owner 未实现 ReconnectNode 该类型时同样报错
	pool2 := &fakePool{ctx: map[string]types.SharedNodeCtx{"node2": &fakePoolNodeCtx{node: struct{}{}}}}
	_, err = BorrowerReconnect[*fakeConn](pool2, "node2", "test", &fakeConn{}, 0)
	assert.NotNil(t, err)
}
