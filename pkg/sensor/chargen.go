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

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var chargenEventTypes = expression.FieldTypeMap{
	"index":      expression.ValueTypeUnsignedInt64,
	"characters": expression.ValueTypeString,
}

func (s *Subscription) decodeChargenEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	e := s.sensor.NewEvent()
	e.Event = &api.TelemetryEvent_Chargen{
		Chargen: &api.ChargenEvent{
			Index:      data["index"].(uint64),
			Characters: data["characters"].(string),
		},
	}

	return e, nil
}

func generateCharacters(start, length uint64) string {
	bytes := make([]byte, length)
	for i := uint64(0); i < length; i++ {
		bytes[i] = ' ' + byte((start+i)%95)
	}
	return string(bytes)
}

// RegisterChargenEventFilter registers a character generation event filter
// with a subscription.
func (s *Subscription) RegisterChargenEventFilter(
	length uint64,
	filter *expression.Expression,
) {
	if length == 0 || length > 1<<16 {
		s.logStatus(
			code.Code_INVALID_ARGUMENT,
			fmt.Sprintf("Chargen length out of range (%d)", length))
		return
	}

	eventID, err := s.sensor.Monitor.RegisterExternalEvent("chargen",
		s.decodeChargenEvent)
	if err != nil {
		s.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Could not register chargen event: %v", err))
		return
	}

	done := make(chan struct{})

	es, err := s.addEventSink(eventID, filter, chargenEventTypes)
	if err != nil {
		s.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Invalid filter expression for chargen filter: %v", err))
		s.sensor.Monitor.UnregisterEvent(eventID)
		return
	}
	es.unregister = func(es *eventSink) {
		s.sensor.Monitor.UnregisterEvent(es.eventID)
		close(done)
	}

	go func() {
		index := uint64(0)
		for {
			select {
			case <-done:
				return
			default:
				monoNow := sys.CurrentMonotonicRaw()
				sampleID := perf.SampleID{
					Time: uint64(monoNow),
				}
				data := perf.TraceEventSampleData{
					"index":      index,
					"characters": generateCharacters(index, length),
				}
				index += length
				s.sensor.Monitor.EnqueueExternalSample(
					eventID, sampleID, data)
			}
		}
	}()
}
