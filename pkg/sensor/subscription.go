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
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/glog"
)

// EventSinkDispatchFn is a function that is called to deliver a telemetry
// event for a subscription.
type EventSinkDispatchFn func(event TelemetryEvent)

type eventSinkUnregisterFn func(es *eventSink)

type eventSink struct {
	subscription *Subscription
	eventID      uint64
	unregister   eventSinkUnregisterFn
	filter       *expression.Expression
	filterTypes  expression.FieldTypeMap
}

// Subscription contains all of the information about a client subscription
// for telemetry events to be delivered by the sensor.
type Subscription struct {
	sensor          *Sensor
	subscriptionID  uint64
	eventGroupID    int32
	counterGroupIDs []int32
	containerFilter *ContainerFilter
	eventSinks      map[uint64]*eventSink
	status          []string
	dispatchFn      EventSinkDispatchFn
}

// Run enables and runs a telemetry event subscription. Canceling the specified
// context will cancel the subscription. For each event matching the
// subscription, the specified dispatch function will be called.
func (s *Subscription) Run(
	ctx context.Context,
	dispatchFn EventSinkDispatchFn,
) ([]string, error) {
	status := s.status
	s.status = nil
	if status != nil {
		for _, st := range status {
			glog.V(1).Infof("Subscription %d: %s",
				s.subscriptionID, st)
		}
	}

	if len(s.eventSinks) == 0 {
		return status, errors.New("Invalid subscription (no filters specified)")
	}

	s.sensor.eventMap.subscribe(s)
	glog.V(2).Infof("Subscription %d registered", s.subscriptionID)

	go func() {
		<-ctx.Done()
		glog.V(2).Infof("Subscription %d control channel closed",
			s.subscriptionID)

		s.Close()
	}()

	if dispatchFn != nil {
		s.dispatchFn = dispatchFn
	}

	if s.eventGroupID != 0 {
		s.sensor.Monitor.EnableGroup(s.eventGroupID)
	}
	for _, id := range s.counterGroupIDs {
		s.sensor.Monitor.EnableGroup(id)
	}

	return status, nil
}

// Close disables a running subscription.
func (s *Subscription) Close() {
	for _, id := range s.counterGroupIDs {
		s.sensor.Monitor.UnregisterEventGroup(id)
	}
	if s.eventGroupID != 0 {
		s.sensor.Monitor.UnregisterEventGroup(s.eventGroupID)
	}
	s.sensor.eventMap.unsubscribe(s, nil)
}

// SetContainerFilter sets a container filter to be used for a subscription.
func (s *Subscription) SetContainerFilter(f *ContainerFilter) {
	s.containerFilter = f
}

func (s *Subscription) addEventSink(
	eventID uint64,
	filterExpression *expression.Expression,
	filterTypes expression.FieldTypeMap,
) (*eventSink, error) {
	es := &eventSink{
		subscription: s,
		eventID:      eventID,
		filterTypes:  filterTypes,
	}

	if filterExpression != nil {
		if err := filterExpression.Validate(filterTypes); err != nil {
			return nil, err
		}

		// If this is a valid kernel filter, attempt to set it as a
		// kernel filter. If it is either not a valid kernel filter or
		// it fails to set as a kernel filter, set the filter in the
		// sink to fallback to evaluation via the expression package.
		// The err checking code here looks a little weird, but it is
		// what is intended.
		var err error
		if err = filterExpression.ValidateKernelFilter(); err == nil {
			err = s.sensor.Monitor.SetFilter(eventID,
				filterExpression.KernelFilterString())
		}
		if err != nil {
			es.filter = filterExpression
		}
	}

	if s.eventSinks == nil {
		s.eventSinks = make(map[uint64]*eventSink)
	}
	s.eventSinks[eventID] = es
	return es, nil
}

func (s *Subscription) removeEventSink(es *eventSink) {
	delete(s.eventSinks, es.eventID)
}

func (s *Subscription) logStatus(st string) {
	s.status = append(s.status, st)
}

func (s *Subscription) createEventGroup() error {
	if s.eventGroupID == 0 {
		if groupID, err := s.sensor.Monitor.RegisterEventGroup(""); err == nil {
			s.eventGroupID = groupID
		} else {
			s.logStatus(
				fmt.Sprintf("Could not create subscription event group: %v",
					err))
			return err
		}
	}
	return nil
}

var perfTypeMapping = map[int32]expression.ValueType{
	perf.TraceEventFieldTypeString: expression.ValueTypeString,

	perf.TraceEventFieldTypeSignedInt8:  expression.ValueTypeSignedInt8,
	perf.TraceEventFieldTypeSignedInt16: expression.ValueTypeSignedInt16,
	perf.TraceEventFieldTypeSignedInt32: expression.ValueTypeSignedInt32,
	perf.TraceEventFieldTypeSignedInt64: expression.ValueTypeSignedInt64,

	perf.TraceEventFieldTypeUnsignedInt8:  expression.ValueTypeUnsignedInt8,
	perf.TraceEventFieldTypeUnsignedInt16: expression.ValueTypeUnsignedInt16,
	perf.TraceEventFieldTypeUnsignedInt32: expression.ValueTypeUnsignedInt32,
	perf.TraceEventFieldTypeUnsignedInt64: expression.ValueTypeUnsignedInt64,
}

func (s *Subscription) registerKprobe(
	address string,
	onReturn bool,
	output string,
	fn perf.TraceEventDecoderFn,
	filterExpr *expression.Expression,
	filterTypes expression.FieldTypeMap,
	options ...perf.RegisterEventOption,
) (*eventSink, error) {
	if err := s.createEventGroup(); err != nil {
		return nil, err
	}
	options = append(options, perf.WithEventGroup(s.eventGroupID))

	eventID, err := s.sensor.RegisterKprobe(address, onReturn, output, fn,
		options...)
	if err != nil {
		s.logStatus(
			fmt.Sprintf("Could not register kprobe %s: %v",
				address, err))
		return nil, err
	}

	// This is a dynamic kprobe -- determine filterTypes dynamically from
	// the kernel.
	if filterExpr != nil && filterTypes == nil {
		kprobeFields := s.sensor.Monitor.RegisteredEventFields(eventID)
		filterTypes = make(expression.FieldTypeMap, len(kprobeFields))
		for k, v := range kprobeFields {
			filterTypes[k] = perfTypeMapping[v]
		}
	}

	es, err := s.addEventSink(eventID, filterExpr, filterTypes)
	if err != nil {
		s.logStatus(
			fmt.Sprintf("Could not register kprobe %s: %v",
				address, err))
		s.sensor.Monitor.UnregisterEvent(eventID)
		return nil, err
	}

	return es, nil
}

func (s *Subscription) registerTracepoint(
	name string,
	fn perf.TraceEventDecoderFn,
	filterExpr *expression.Expression,
	filterTypes expression.FieldTypeMap,
	options ...perf.RegisterEventOption,
) (*eventSink, error) {
	if err := s.createEventGroup(); err != nil {
		return nil, err
	}
	options = append(options, perf.WithEventGroup(s.eventGroupID))

	eventID, err := s.sensor.Monitor.RegisterTracepoint(name, fn,
		options...)
	if err != nil {
		s.logStatus(
			fmt.Sprintf("Could not register tracepoint %s: %v",
				name, err))
		return nil, err
	}

	es, err := s.addEventSink(eventID, filterExpr, filterTypes)
	if err != nil {
		s.logStatus(
			fmt.Sprintf("Could not register tracepoint %s: %v",
				name, err))
		s.sensor.Monitor.UnregisterEvent(eventID)
		return nil, err
	}

	return es, nil
}

//
// safeSubscriptionMap
// map[uint64]map[int32]*eventSink
//

type subscriptionMap map[uint64]map[int32]*eventSink

func newSubscriptionMap() subscriptionMap {
	return make(subscriptionMap)
}

type safeSubscriptionMap struct {
	sync.Mutex              // used only by writers
	active     atomic.Value // map[uint64]map[int32]*eventSink
}

func newSafeSubscriptionMap() *safeSubscriptionMap {
	return &safeSubscriptionMap{}
}

func (ssm *safeSubscriptionMap) getMap() subscriptionMap {
	if value := ssm.active.Load(); value != nil {
		return value.(subscriptionMap)
	}
	return nil
}

func (ssm *safeSubscriptionMap) subscribe(subscr *Subscription) {
	ssm.Lock()
	defer ssm.Unlock()

	om := ssm.getMap()
	nm := make(subscriptionMap, len(om)+len(subscr.eventSinks))

	if om != nil {
		for k, v := range om {
			c := make(map[int32]*eventSink, len(v))
			for k2, v2 := range v {
				c[k2] = v2
			}
			nm[k] = c
		}
	}

	for eventID, es := range subscr.eventSinks {
		subscriptionMap, ok := nm[eventID]
		if !ok {
			subscriptionMap = make(map[int32]*eventSink)
			nm[eventID] = subscriptionMap
		}
		subscriptionMap[subscr.eventGroupID] = es
	}

	ssm.active.Store(nm)
}

func (ssm *safeSubscriptionMap) unsubscribe(
	subscr *Subscription,
	f func(uint64),
) {
	var (
		deadEventIDs   []uint64
		deadEventSinks []*eventSink
	)

	ssm.Lock()
	if om := ssm.getMap(); om != nil {
		subscriptionID := subscr.eventGroupID
		nm := make(subscriptionMap, len(om))
		for eventID, v := range om {
			var m map[int32]*eventSink
			for ID, es := range v {
				if ID != subscriptionID {
					if m == nil {
						m = make(map[int32]*eventSink)
					}
					m[ID] = es
				} else if es.unregister != nil {
					deadEventSinks = append(deadEventSinks,
						es)
				}
			}
			if m == nil {
				deadEventIDs = append(deadEventIDs, eventID)
			} else {
				nm[eventID] = m
			}
		}
		ssm.active.Store(nm)
	}
	ssm.Unlock()

	for _, es := range deadEventSinks {
		es.unregister(es)
	}
	if f != nil {
		for _, eventID := range deadEventIDs {
			f(eventID)
		}
	}
}
