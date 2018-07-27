// Copyright 2017 Capsule8, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package perf

import (
	"sync"
	"sync/atomic"
)

//
// safeUInt64Map
// map[uint64]uint64
//

type uint64Map map[uint64]uint64

func newUInt64Map() uint64Map {
	return make(uint64Map)
}

type safeUInt64Map struct {
	sync.Mutex              // used only by writers
	active     atomic.Value // map[uint64]uint64
}

func newSafeUInt64Map() *safeUInt64Map {
	return &safeUInt64Map{}
}

func (m *safeUInt64Map) getMap() uint64Map {
	value := m.active.Load()
	if value == nil {
		return nil
	}
	return value.(uint64Map)
}

func (m *safeUInt64Map) removeInPlace(ids []uint64) {
	em := m.getMap()
	if em == nil {
		return
	}

	for _, id := range ids {
		delete(em, id)
	}
}

func (m *safeUInt64Map) remove(ids []uint64) {
	m.Lock()
	defer m.Unlock()

	om := m.getMap()
	nm := newUInt64Map()
	if om != nil {
		for k, v := range om {
			nm[k] = v
		}
	}
	for _, id := range ids {
		delete(nm, id)
	}

	m.active.Store(nm)
}

func (m *safeUInt64Map) updateInPlace(mfrom uint64Map) {
	mto := m.getMap()
	if mto == nil {
		mto = newUInt64Map()
		m.active.Store(mto)
	}

	for k, v := range mfrom {
		mto[k] = v
	}
}

func (m *safeUInt64Map) update(mfrom uint64Map) {
	m.Lock()
	defer m.Unlock()

	om := m.getMap()
	nm := newUInt64Map()
	if om != nil {
		for k, v := range om {
			nm[k] = v
		}
	}
	for k, v := range mfrom {
		nm[k] = v
	}

	m.active.Store(nm)
}

//
// safeEventAttrMap
// map[uint64]EventAttr
//

type eventAttrMap map[uint64]EventAttr

func newEventAttrMap() eventAttrMap {
	return make(eventAttrMap)
}

type safeEventAttrMap struct {
	sync.Mutex              // used only by writers
	active     atomic.Value // map[uint64]*EventAttr
}

func newSafeEventAttrMap() *safeEventAttrMap {
	return &safeEventAttrMap{}
}

func (m *safeEventAttrMap) getMap() eventAttrMap {
	value := m.active.Load()
	if value == nil {
		return nil
	}
	return value.(eventAttrMap)
}

func (m *safeEventAttrMap) removeInPlace(ids []uint64) {
	em := m.getMap()
	if em == nil {
		return
	}

	for _, id := range ids {
		delete(em, id)
	}
}

func (m *safeEventAttrMap) remove(ids []uint64) {
	m.Lock()
	defer m.Unlock()

	oem := m.getMap()
	nem := newEventAttrMap()
	if oem != nil {
		for k, v := range oem {
			nem[k] = v
		}
	}
	for _, id := range ids {
		delete(nem, id)
	}

	m.active.Store(nem)
}

func (m *safeEventAttrMap) updateInPlace(emfrom eventAttrMap) {
	em := m.getMap()
	if em == nil {
		em = newEventAttrMap()
		m.active.Store(em)
	}

	for k, v := range emfrom {
		em[k] = v
	}
}

func (m *safeEventAttrMap) update(emfrom eventAttrMap) {
	m.Lock()
	defer m.Unlock()

	oem := m.getMap()
	nem := newEventAttrMap()
	if oem != nil {
		for k, v := range oem {
			nem[k] = v
		}
	}
	for k, v := range emfrom {
		nem[k] = v
	}

	m.active.Store(nem)
}

//
// safeRegisteredEventMap
// map[uint64]registeredEvent
//

type registeredEventMap map[uint64]*registeredEvent

func newRegisteredEventMap() registeredEventMap {
	return make(registeredEventMap)
}

type safeRegisteredEventMap struct {
	sync.Mutex              // used only by writers
	active     atomic.Value // map[uint64]registeredEvent
}

func newSafeRegisteredEventMap() *safeRegisteredEventMap {
	return &safeRegisteredEventMap{}
}

func (m *safeRegisteredEventMap) getMap() registeredEventMap {
	value := m.active.Load()
	if value == nil {
		return nil
	}
	return value.(registeredEventMap)
}

func (m *safeRegisteredEventMap) insertInPlace(eventID uint64, event *registeredEvent) {
	em := m.getMap()
	if em == nil {
		em = newRegisteredEventMap()
		m.active.Store(em)
	}

	em[eventID] = event
}

func (m *safeRegisteredEventMap) insert(eventID uint64, event *registeredEvent) {
	m.Lock()
	defer m.Unlock()

	oem := m.getMap()
	nem := newRegisteredEventMap()
	if oem != nil {
		for k, v := range oem {
			nem[k] = v
		}
	}
	nem[eventID] = event

	m.active.Store(nem)
}

func (m *safeRegisteredEventMap) lookup(eventID uint64) (*registeredEvent, bool) {
	em := m.getMap()
	if em != nil {
		e, ok := em[eventID]
		return e, ok
	}
	return nil, false
}

func (m *safeRegisteredEventMap) removeInPlace(eventID uint64) {
	em := m.getMap()
	if em == nil {
		return
	}

	delete(em, eventID)
}

func (m *safeRegisteredEventMap) remove(eventID uint64) {
	m.Lock()
	defer m.Unlock()

	oem := m.getMap()
	nem := newRegisteredEventMap()
	if oem != nil {
		for k, v := range oem {
			if k != eventID {
				nem[k] = v
			}
		}
	}

	m.active.Store(nem)
}

//
// safePerfGroupLeaderMap
// map[uint64]*perfGroupLeader
//

type perfGroupLeaderMap map[uint64]*perfGroupLeader

func newPerfGroupLeaderMap() perfGroupLeaderMap {
	return make(perfGroupLeaderMap)
}

type safePerfGroupLeaderMap struct {
	sync.Mutex              // used only by writers
	active     atomic.Value // map[int]*perfGroupLeader
}

func newSafePerfGroupLeaderMap() *safePerfGroupLeaderMap {
	return &safePerfGroupLeaderMap{}
}

func (m *safePerfGroupLeaderMap) getMap() perfGroupLeaderMap {
	value := m.active.Load()
	if value == nil {
		return nil
	}
	return value.(perfGroupLeaderMap)
}

func (m *safePerfGroupLeaderMap) lookup(id uint64) (*perfGroupLeader, bool) {
	t := m.getMap()
	if t == nil {
		return nil, false
	}
	pgl, ok := t[id]
	return pgl, ok
}

func (m *safePerfGroupLeaderMap) removeInPlace(ids map[uint64]struct{}) {
	nm := m.getMap()
	if nm != nil {
		for id := range ids {
			delete(nm, id)
		}
	}
}

func (m *safePerfGroupLeaderMap) remove(ids map[uint64]struct{}) {
	m.Lock()
	defer m.Unlock()

	om := m.getMap()
	nm := newPerfGroupLeaderMap()
	if om != nil {
		for k, v := range om {
			if _, ok := ids[k]; !ok {
				nm[k] = v
			}
		}
	}
	m.active.Store(nm)
}

func (m *safePerfGroupLeaderMap) updateInPlace(leaders []*perfGroupLeader) {
	nm := m.getMap()
	if nm == nil {
		nm = newPerfGroupLeaderMap()
		m.active.Store(nm)
	}
	for _, pgl := range leaders {
		nm[pgl.source.SourceID()] = pgl
	}
}

func (m *safePerfGroupLeaderMap) update(leaders []*perfGroupLeader) {
	m.Lock()
	defer m.Unlock()

	om := m.getMap()
	nm := newPerfGroupLeaderMap()
	if om != nil {
		for k, v := range om {
			nm[k] = v
		}
	}
	for _, pgl := range leaders {
		nm[pgl.source.SourceID()] = pgl
	}
	m.active.Store(nm)
}
