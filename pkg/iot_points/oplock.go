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

import "sync"

// OpLocks associates an operation lock per connection instance (keyed by pointer or interface value),
// serializing concurrent read/write on shared connections.
type OpLocks struct {
	m sync.Map // map[any]*sync.Mutex
}

// Lock returns the mutex for the given connection key, creating one if absent.
func (o *OpLocks) Lock(key any) *sync.Mutex {
	v, _ := o.m.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// Delete removes the lock entry for the given connection key (call on reconnect/destroy to avoid leaks).
func (o *OpLocks) Delete(key any) {
	o.m.Delete(key)
}

// Has reports whether a lock entry exists for the given key.
func (o *OpLocks) Has(key any) bool {
	_, ok := o.m.Load(key)
	return ok
}
