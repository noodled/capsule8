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
	"time"

	api "github.com/capsule8/capsule8/api/v0"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var tickerEventTypes = expression.FieldTypeMap{
	"seconds":     expression.ValueTypeSignedInt64,
	"nanoseconds": expression.ValueTypeSignedInt64,
}

func (s *Subscription) decodeTickerEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	e := s.sensor.NewEvent()
	e.Event = &api.TelemetryEvent_Ticker{
		Ticker: &api.TickerEvent{
			Seconds:     data["seconds"].(int64),
			Nanoseconds: data["nanoseconds"].(int64),
		},
	}
	return e, nil
}

// RegisterTickerEventFilter registers a ticker event filter with a
// subscription.
func (s *Subscription) RegisterTickerEventFilter(
	interval int64,
	filter *expression.Expression,
) {
	if interval <= 0 {
		s.logStatus(
			code.Code_INVALID_ARGUMENT,
			fmt.Sprintf("Invalid ticker interval: %d", interval))
		return
	}

	eventID, err := s.sensor.Monitor.RegisterExternalEvent("ticker",
		s.decodeTickerEvent)
	if err != nil {
		s.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Could not register ticker event: %v", err))
		return
	}

	done := make(chan struct{})

	es, err := s.addEventSink(eventID, filter, tickerEventTypes)
	if err != nil {
		s.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Invalid filter expression for ticker filter: %v", err))
		s.sensor.Monitor.UnregisterEvent(eventID)
		return
	}
	es.unregister = func(es *eventSink) {
		s.sensor.Monitor.UnregisterEvent(es.eventID)
		close(done)
	}

	go func() {
		ticker := time.NewTicker(time.Duration(interval))
		for {
			select {
			case <-done:
				ticker.Stop()
				return
			case <-ticker.C:
				monoNow := sys.CurrentMonotonicRaw()
				sampleID := perf.SampleID{
					Time: uint64(monoNow),
				}
				now := time.Now()
				data := perf.TraceEventSampleData{
					"seconds":     int64(now.Unix()),
					"nanoseconds": int64(now.UnixNano()),
				}
				s.sensor.Monitor.EnqueueExternalSample(
					eventID, sampleID, data)
			}
		}
	}()
}
