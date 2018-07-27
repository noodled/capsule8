// Copyright 2018 Capsule8, Inc.
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
	"time"

	"github.com/capsule8/capsule8/pkg/sys"

	"golang.org/x/sys/unix"
)

var nextStubSourceID uint64

// StubEventSource is an event source implementation used as part of
// StubEventSourceController.
type StubEventSource struct {
	sourceID uint64 // Use the SourceID method to read this

	CloseCount     int
	DisableCount   int
	EnableCount    int
	SetFilterCount int
	Filter         string
	Enabled        bool
	Closed         bool
}

func newStubEventSource(attr EventAttr) *StubEventSource {
	newSource := &StubEventSource{}
	newSource.init(attr)
	return newSource
}

// Close terminates the event source.
func (s *StubEventSource) Close() error {
	s.CloseCount++
	s.Closed = true
	return nil
}

// Disable disables the event source without terminating it. The event source
// may be re-enabled. It is not an error to disable an already disabled source.
func (s *StubEventSource) Disable() error {
	s.DisableCount++
	s.Enabled = false
	return nil
}

// Enable enables the event source. It is not an error to enable an already
// enabled source.
func (s *StubEventSource) Enable() error {
	s.EnableCount++
	s.Enabled = true
	return nil
}

// SetFilter sets a filter for an event source. Using the empty string for the
// filter clears the filter.
func (s *StubEventSource) SetFilter(filter string) error {
	s.SetFilterCount++
	s.Filter = filter
	return nil
}

// SourceID returns a unique identifier for the EventSource.
func (s *StubEventSource) SourceID() uint64 {
	return s.sourceID
}

func (s *StubEventSource) init(attr EventAttr) {
	s.sourceID = atomic.AddUint64(&nextStubSourceID, 1)
	s.Enabled = !attr.Disabled
}

type stubSample struct {
	sample Sample
	err    error
}

// StubEventSourceLeader is an event source implementation used as part of
// StubEventSourceController.
type StubEventSourceLeader struct {
	StubEventSource
	pid, cpu   int
	controller *StubEventSourceController
	queue      []stubSample
}

func newStubEventSourceLeader(attr EventAttr, pid, cpu int) *StubEventSourceLeader {
	newSource := &StubEventSourceLeader{
		pid: pid,
		cpu: cpu,
	}
	newSource.StubEventSource.init(attr)
	return newSource
}

// Close terminates the event source.
func (s *StubEventSourceLeader) Close() error {
	var err error
	if err = s.StubEventSource.Close(); err == nil && s.controller != nil {
		s.controller.lock.Lock()
		delete(s.controller.activeLeaders, s.sourceID)
		s.controller.lock.Unlock()
	}
	return err
}

// NewEventSource creates a new EventSource that is a member of the group that
// this EventSourceLeader leads.
func (s *StubEventSourceLeader) NewEventSource(
	attr EventAttr,
	flags uintptr,
) (EventSource, error) {
	return newStubEventSource(attr), nil
}

// Read retrieves available samples, calling the specified function for each
// sample retrieved.
func (s *StubEventSourceLeader) Read(
	attrMap map[uint64]EventAttr,
	f func(Sample, error),
) {
	s.controller.lock.Lock()
	for s.queue != nil {
		queue := s.queue
		s.queue = nil
		s.controller.lock.Unlock()
		for _, s := range queue {
			f(s.sample, s.err)
		}
		s.controller.lock.Lock()
	}
	s.controller.lock.Unlock()
}

// EnqueueSample enqueues a sample and/or error to be retrived via Read.
func (s *StubEventSourceLeader) EnqueueSample(sample Sample, err error) {
	s.controller.lock.Lock()
	s.queue = append(s.queue, stubSample{sample, err})
	s.controller.lock.Unlock()
}

// StubEventSourceController is a stub implementation of EventSourceController
// intended primarily for use in testing EventMonitor.
type StubEventSourceController struct {
	setTimeoutAtChannel chan int64
	wakeupChannel       chan bool

	lock          sync.RWMutex
	activeLeaders map[uint64]*StubEventSourceLeader
}

// NewStubEventSourceController creates a new StubEventSourceController and
// initializes it for use.
func NewStubEventSourceController() *StubEventSourceController {
	return &StubEventSourceController{
		setTimeoutAtChannel: make(chan int64, 1024),
		wakeupChannel:       make(chan bool, 1024),
		activeLeaders:       make(map[uint64]*StubEventSourceLeader),
	}
}

// Close closes the EventSourceController, cleaning up any resources that it
// may have reserved for itself. The EventSourceController is no longer usable
// after this function completes.
func (c *StubEventSourceController) Close() {
	c.setTimeoutAtChannel = nil
	c.wakeupChannel = nil
	c.activeLeaders = nil
}

// NewEventSourceLeader creates a new event source as a group leader. Group
// leaders may or may not have event sources as children.
func (c *StubEventSourceController) NewEventSourceLeader(
	attr EventAttr,
	pid, cpu int,
	flags uintptr,
) (EventSourceLeader, error) {
	l := newStubEventSourceLeader(attr, pid, cpu)
	l.controller = c
	c.lock.Lock()
	c.activeLeaders[l.sourceID] = l
	c.lock.Unlock()
	return l, nil
}

func (c *StubEventSourceController) hasPendingSamples() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()

	for _, l := range c.activeLeaders {
		if len(l.queue) > 0 {
			return true
		}
	}
	return false
}

// Wait pauses execution until events become available for processing or the
// specified time arrives. The time is specified using the system monotonic
// clock. If the time is 0 or has already passed, Wait will return immediately
// if no events are ready for processing. If the time is negative, Wait will
// wait indefinitely until events become available. If the specified time
// arrives before any events become available, the function will return
// unix.ETIMEDOUT. The return from Wait will be nil when events are ready for
// processing.
func (c *StubEventSourceController) Wait(timeoutAt int64) error {
	var t *time.Timer
	defer func() {
		if t != nil {
			t.Stop()
		}

		// Drain anything pending on the channels
		done := false
		for !done {
			select {
			case <-c.setTimeoutAtChannel:
			case <-c.wakeupChannel:
			default:
				done = true
			}
		}
	}()

	for {
		switch timeoutAt {
		case -1:
			if t != nil {
				t.Stop()
				t = nil
			}
			if c.hasPendingSamples() {
				return nil
			}
			select {
			case timeoutAt = <-c.setTimeoutAtChannel:
			case <-c.wakeupChannel:
			}
		case 0:
			if c.hasPendingSamples() {
				return nil
			}
			return unix.ETIMEDOUT
		default:
			if c.hasPendingSamples() {
				return nil
			}
			now := sys.CurrentMonotonicRaw()
			if now <= timeoutAt {
				return unix.ETIMEDOUT
			}
			d := time.Duration(timeoutAt - now)
			if t == nil {
				t = time.NewTimer(d)
			} else {
				t.Reset(d)
			}
			select {
			case v := <-c.setTimeoutAtChannel:
				if v < timeoutAt {
					timeoutAt = v
				}
			case <-c.wakeupChannel:
			case <-t.C:
			}
		}
	}
	return nil
}

// SetTimeoutAt sets the time at which the currently paused Wait call will
// timeout. The behavior of the timeout value is the same as for Wait itself.
func (c *StubEventSourceController) SetTimeoutAt(timeoutAt int64) error {
	c.setTimeoutAtChannel <- timeoutAt
	return nil
}

// Wakeup wakes up any goroutine blocked in Wait.
func (c *StubEventSourceController) Wakeup() {
	c.wakeupChannel <- true
}
