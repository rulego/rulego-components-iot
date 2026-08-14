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
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rulego/rulego/api/types"
)

// SharedConn is the subset of base.SharedNode[T] the runner needs.
type SharedConn[T any] interface {
	GetSafely() (T, error)
	SetStatus(types.NodeStatus, string)
}

// ReconnectNode lets a ref:// borrower delegate reconnect to the node that
// owns the connection (the Read and Write nodes of one protocol both implement
// it with the same client type).
type ReconnectNode[T any] interface {
	ReconnectNode(old T, attempt int) (T, error)
}

// RunOpts carries the per-node retry policy and client lifecycle hooks.
type RunOpts[T any] struct {
	Shared    SharedConn[T]
	Reconnect func(old T, attempt int) (T, error)
	// OpLocks serializes operations on the shared client; nil when the client
	// is safe for concurrent use.
	OpLocks *OpLocks
	// LockWait bounds how long acquiring the op lock may queue behind a stuck
	// operation; 0 waits forever (legacy behavior).
	LockWait time.Duration
	Logger   types.Logger
	// Prefix is the log prefix, e.g. "[SNMP]".
	Prefix string
	// RetryOnTimeout keeps retrying after timeout errors. Connectionless (UDP)
	// protocols leave it false: a silent peer stays silent on a fresh socket.
	RetryOnTimeout bool
	// MaxRetries caps reconnect rounds; 0 uses DefaultMaxRetries.
	MaxRetries int
}

// RunRead reads points with reconnect-retry. On success the data list is
// marshaled into msg as JSON and routed Success; on exhaustion the last error
// routes Failure. Status flips to Connected on success, Reconnecting while
// retrying.
func RunRead[T any](ctx types.RuleContext, msg types.RuleMsg, read func(client T) ([]Data, error), o RunOpts[T]) {
	client, err := o.Shared.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	maxRetries := o.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	var lastErr error
	for retry := 0; ; retry++ {
		release, ok := o.acquire(client)
		if !ok {
			ctx.TellFailure(msg, fmt.Errorf("%s connection busy: previous operation still in progress", o.Prefix))
			return
		}
		data, rerr := read(client)
		release()
		if rerr == nil {
			b, mErr := json.Marshal(data)
			if mErr != nil {
				ctx.TellFailure(msg, mErr)
				return
			}
			msg.SetDataType(types.JSON)
			msg.SetData(string(b))
			o.Shared.SetStatus(types.StatusConnected, "")
			ctx.TellSuccess(msg)
			return
		}
		lastErr = rerr
		if IsTimeoutErr(rerr) && !o.RetryOnTimeout {
			o.Shared.SetStatus(types.StatusReconnecting, rerr.Error())
			ctx.TellFailure(msg, rerr)
			return
		}
		if retry >= maxRetries {
			break
		}
		o.warnf("read failed (retry %d/%d): %v, reconnecting...", retry+1, maxRetries, rerr)
		o.Shared.SetStatus(types.StatusReconnecting, rerr.Error())
		newClient, cerr := o.Reconnect(client, retry)
		if cerr != nil {
			ctx.TellFailure(msg, cerr)
			return
		}
		if o.OpLocks != nil {
			o.OpLocks.Delete(any(client))
		}
		client = newClient
	}
	ctx.TellFailure(msg, lastErr)
}

// RunWrite writes points with the same reconnect-retry policy; success routes
// Success without touching msg data.
func RunWrite[T any](ctx types.RuleContext, msg types.RuleMsg, write func(client T) error, o RunOpts[T]) {
	client, err := o.Shared.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	maxRetries := o.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	var lastErr error
	for retry := 0; ; retry++ {
		release, ok := o.acquire(client)
		if !ok {
			ctx.TellFailure(msg, fmt.Errorf("%s connection busy: previous operation still in progress", o.Prefix))
			return
		}
		werr := write(client)
		release()
		if werr == nil {
			o.Shared.SetStatus(types.StatusConnected, "")
			ctx.TellSuccess(msg)
			return
		}
		lastErr = werr
		if IsTimeoutErr(werr) && !o.RetryOnTimeout {
			o.Shared.SetStatus(types.StatusReconnecting, werr.Error())
			ctx.TellFailure(msg, werr)
			return
		}
		if retry >= maxRetries {
			break
		}
		o.warnf("write failed (retry %d/%d): %v, reconnecting...", retry+1, maxRetries, werr)
		o.Shared.SetStatus(types.StatusReconnecting, werr.Error())
		newClient, cerr := o.Reconnect(client, retry)
		if cerr != nil {
			ctx.TellFailure(msg, cerr)
			return
		}
		if o.OpLocks != nil {
			o.OpLocks.Delete(any(client))
		}
		client = newClient
	}
	ctx.TellFailure(msg, lastErr)
}

func (o RunOpts[T]) acquire(client T) (release func(), ok bool) {
	if o.OpLocks == nil {
		return func() {}, true
	}
	if o.LockWait > 0 {
		return o.OpLocks.TryLockTimeout(any(client), o.LockWait)
	}
	mu := o.OpLocks.Lock(any(client))
	mu.Lock()
	return mu.Unlock, true
}

func (o RunOpts[T]) warnf(format string, v ...interface{}) {
	if o.Logger != nil {
		o.Logger.Warnf(o.Prefix+" "+format, v...)
	}
}

// BorrowerReconnect routes a ref:// borrower's reconnect to the owner node in
// the shared pool. It errors when there is no owning node to delegate to.
func BorrowerReconnect[T any](pool types.NodePool, instanceId, prefix string, old T, attempt int) (T, error) {
	var zero T
	if pool != nil {
		if nodeCtx, ok := pool.Get(instanceId); ok {
			if source, ok := nodeCtx.GetNode().(ReconnectNode[T]); ok {
				return source.ReconnectNode(old, attempt)
			}
		}
	}
	return zero, fmt.Errorf("%s ref://%s borrower does not own the connection", prefix, instanceId)
}

// RebuildConn is the reconnect body for connection-owning nodes: unless another
// goroutine already replaced the client, it closes the old one, waits the
// backoff and installs a fresh client.
func RebuildConn[T any](locker *sync.Mutex, get func() (T, error), refresh func(T), old T, attempt int, newClient func() (T, error), closeClient func(T) error) (T, error) {
	locker.Lock()
	defer locker.Unlock()
	current, err := get()
	if err != nil {
		var zero T
		return zero, err
	}
	if any(current) != any(old) {
		return current, nil
	}
	if closeClient != nil {
		_ = closeClient(old)
	}
	time.Sleep(BackoffFor(attempt))
	c, err := newClient()
	if err != nil {
		var zero T
		return zero, err
	}
	refresh(c)
	return c, nil
}
