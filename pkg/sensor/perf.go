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

package sensor

import (
	"fmt"

	api "github.com/capsule8/capsule8/api/v0"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
)

func (s *Subscription) decodePerfCounterEvent(
	sample *perf.SampleRecord,
	counters []perf.CounterEventValue,
	totalTimeEnabled uint64,
	totalTimeRunning uint64,
) (interface{}, error) {
	event := s.sensor.NewEventFromSample(sample, nil)
	if event == nil {
		return nil, nil
	}

	values := make([]*api.PerformanceEventValue, len(counters))
	for i, v := range counters {
		var t api.PerformanceEventType
		switch v.EventType {
		case perf.EventTypeHardware:
			t = api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE
		case perf.EventTypeHardwareCache:
			t = api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE
		case perf.EventTypeSoftware:
			t = api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_SOFTWARE
		}
		values[i] = &api.PerformanceEventValue{
			Type:   t,
			Config: v.Config,
			Value:  v.Value,
		}
	}

	ev := &api.PerformanceEvent{
		TotalTimeEnabled: totalTimeEnabled,
		TotalTimeRunning: totalTimeRunning,
		Values:           values,
	}

	event.Event = &api.TelemetryEvent_Performance{
		Performance: ev,
	}
	return event, nil
}

// RegisterPerformanceEventFilter registers a performance event filter with a
// subscription.
func (s *Subscription) RegisterPerformanceEventFilter(
	attr perf.EventAttr,
	counters []perf.CounterEventGroupMember,
) {
	eventName := "Performance Counters"
	groupID, eventID, err := s.sensor.Monitor.RegisterCounterEventGroup(
		eventName, counters, s.decodePerfCounterEvent,
		perf.WithEventAttr(&attr))
	if err != nil {
		s.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Could not register %s performance event: %v",
				eventName, err))
	} else {
		s.counterGroupIDs = append(s.counterGroupIDs, groupID)
		s.addEventSink(eventID, nil, nil)
	}
}
