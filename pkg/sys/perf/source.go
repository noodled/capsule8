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

// EventSource defines the interface for an event source.
type EventSource interface {
	// Close terminates the event source.
	Close() error

	// Disable disables the event source without terminating it. The event
	// source may be re-enabled. It is not an error to disable an already
	// disabled source.
	Disable() error

	// Enable enables the event source. It is not an error to enable an
	// already enabled source.
	Enable() error

	// SetFilter sets a filter for an event source. Using the empty string
	// for the filter clears the filter.
	SetFilter(filter string) error

	// SourceID returns a unique identifier for the EventSource.
	SourceID() uint64
}

// EventSourceLeader defines the interface for an event source that is also a
// group leader.
type EventSourceLeader interface {
	EventSource

	// NewEventSource creates a new EventSource that is a member of the
	// group that this EventSourceLeader leads.
	NewEventSource(attr EventAttr, flags uintptr) (EventSource, error)

	// Read retrieves available samples, calling the specified function for
	// each sample retrieved.
	Read(attrMap map[uint64]EventAttr, f func(Sample, error))
}

// EventSourceController defines the interface with which EventMonitor will
// obtain event information.
type EventSourceController interface {
	// Close closes the EventSourceController, cleaning up any resources
	// that it may have reserved for itself. The EventSourceController is
	// no longer usable after this function completes.
	Close()

	// NewEventSourceLeader creates a new event source as a group leader.
	// Group leaders may or may not have event sources as children.
	NewEventSourceLeader(attr EventAttr, pid, cpu int, flags uintptr) (EventSourceLeader, error)

	// Wait pauses execution until events become available for processing
	// or the specified time arrives. The time is specified using the
	// system monotonic clock. If the time is 0 or has already passed, Wait
	// will return immediately if no events are ready for processing. If
	// the time is negative, Wait will wait indefinitely until events
	// become available. If the specified time arrives before any events
	// become available, the function will return unix.ETIMEDOUT. The
	// return from Wait will be nil when events are ready for processing.
	Wait(timeoutAt int64) error

	// SetTimeoutAt sets the time at which the currently paused Wait call
	// will timeout. The behavior of the timeout value is the same as for
	// Wait itself.
	SetTimeoutAt(timeoutAt int64) error
}
