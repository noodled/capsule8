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
	"sync"
	"sync/atomic"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/glog"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var syscallEnterEventTypes = expression.FieldTypeMap{
	"id":   expression.ValueTypeSignedInt64,
	"arg0": expression.ValueTypeUnsignedInt64,
	"arg1": expression.ValueTypeUnsignedInt64,
	"arg2": expression.ValueTypeUnsignedInt64,
	"arg3": expression.ValueTypeUnsignedInt64,
	"arg4": expression.ValueTypeUnsignedInt64,
	"arg5": expression.ValueTypeUnsignedInt64,
}

var syscallExitEventTypes = expression.FieldTypeMap{
	"id":  expression.ValueTypeSignedInt64,
	"ret": expression.ValueTypeSignedInt64,
}

func decodeDummySysEnter(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return nil, nil
}

func (s *Subscription) decodeSyscallTraceEnter(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	ev := s.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	ev.Event = &api.TelemetryEvent_Syscall{
		Syscall: &api.SyscallEvent{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,
			Id:   data["id"].(int64),
			Arg0: data["arg0"].(uint64),
			Arg1: data["arg1"].(uint64),
			Arg2: data["arg2"].(uint64),
			Arg3: data["arg3"].(uint64),
			Arg4: data["arg4"].(uint64),
			Arg5: data["arg5"].(uint64),
		},
	}

	return ev, nil
}

func (s *Subscription) decodeSysExit(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	ev := s.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	ev.Event = &api.TelemetryEvent_Syscall{
		Syscall: &api.SyscallEvent{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT,
			Id:   data["id"].(int64),
			Ret:  data["ret"].(int64),
		},
	}

	return ev, nil
}

func containsIDFilter(expr *api.Expression) bool {
	if expr != nil {
		switch expr.GetType() {
		case api.Expression_LOGICAL_AND:
			operands := expr.GetBinaryOp()
			return containsIDFilter(operands.Lhs) ||
				containsIDFilter(operands.Rhs)
		case api.Expression_LOGICAL_OR:
			operands := expr.GetBinaryOp()
			return containsIDFilter(operands.Lhs) &&
				containsIDFilter(operands.Rhs)
		case api.Expression_EQ:
			operands := expr.GetBinaryOp()
			if operands.Lhs.GetType() != api.Expression_IDENTIFIER {
				return false
			}
			if operands.Lhs.GetIdentifier() != "id" {
				return false
			}
			return true
		}
	}
	return false
}

const (
	syscallNewEnterKprobeAddress string = "syscall_trace_enter_phase1"
	syscallOldEnterKprobeAddress string = "syscall_trace_enter"

	// These offsets index into the x86_64 version of struct pt_regs
	// in the kernel. This is a stable structure.
	syscallEnterKprobeFetchargs string = "id=+120(%di):s64 " + // orig_ax
		"arg0=+112(%di):u64 " + // di
		"arg1=+104(%di):u64 " + // si
		"arg2=+96(%di):u64 " + // dx
		"arg3=+56(%di):u64 " + // r10
		"arg4=+72(%di):u64 " + // r8
		"arg5=+64(%di):u64" // r9
)

var (
	syscallOnce      sync.Once
	syscallEnterName string
	syscallExitName  string
)

func (s *Subscription) initSyscallNames() {
	// Different sensor instances could have different tracing dirs, but
	// ultimately they're all still coming from the same running kernel,
	// so the tracepoint names are not going to change. So while this might
	// appear to be a bit shady, it's perfectly safe.
	syscallEnterName = "raw_syscalls/sys_enter"
	if s.sensor.Monitor.DoesTracepointExist(syscallEnterName) {
		syscallExitName = "raw_syscalls/sys_exit"
	} else {
		syscallEnterName = "syscalls/sys_enter"
		if !s.sensor.Monitor.DoesTracepointExist(syscallEnterName) {
			glog.Fatal("No syscall sys_enter tracepoint exists!")
		}
		syscallExitName = "syscalls/sys_exit"
	}
}

// RegisterSyscallEnterEventFilter registers a syscall enter event filter with
// a subscription.
func (s *Subscription) RegisterSyscallEnterEventFilter(
	filter *expression.Expression,
) {
	syscallOnce.Do(s.initSyscallNames)

	// Create the dummy syscall event. This event is needed to put
	// the kernel into a mode where it'll make the function calls
	// needed to make the kprobe we'll add fire. Add the tracepoint,
	// but make sure it never adds events into the ringbuffer by
	// using a filter that will never evaluate true. It also never
	// gets enabled, but just creating it is enough.
	//
	// For kernels older than 3.x, create this dummy event in all
	// event groups, because we cannot remove it when we don't need
	// it anymore due to bugs in CentOS 6.x kernels (2.6.32).
	var (
		err     error
		eventID uint64
	)

	major, _, _ := sys.KernelVersion()
	if major < 3 {
		if err = s.createEventGroup(); err != nil {
			s.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Could not create subscription event group: %v", err))
			return
		}
		_, err = s.sensor.Monitor.RegisterTracepoint(
			syscallEnterName, decodeDummySysEnter,
			perf.WithEventGroup(s.eventGroupID),
			perf.WithFilter("id == 0x7fffffff"))
		if err != nil {
			s.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Could not register dummy syscall event %s: %v",
					syscallEnterName, err))
			return
		}
	} else if atomic.AddInt64(&s.sensor.dummySyscallEventCount, 1) == 1 {
		eventID, err = s.sensor.Monitor.RegisterTracepoint(
			syscallEnterName, decodeDummySysEnter,
			perf.WithEventGroup(0),
			perf.WithFilter("id == 0x7fffffff"))
		if err != nil {
			s.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Could not register dummy syscall event %s: %v",
					syscallEnterName, err))
			atomic.AddInt64(&s.sensor.dummySyscallEventCount, -1)
			return
		}
		s.sensor.dummySyscallEventID = eventID
	}

	// There are two possible kprobes. Newer kernels (>= 4.1) have
	// refactored syscall entry code, so syscall_trace_enter_phase1
	// is the right one, but for older kernels syscall_trace_enter
	// is the right one. Both have the same signature, so the
	// fetchargs doesn't have to change. Try the new probe first,
	// because the old probe will also set in the newer kernels,
	// but it won't fire.
	kprobeSymbol := syscallNewEnterKprobeAddress
	if !s.sensor.IsKernelSymbolAvailable(kprobeSymbol) {
		kprobeSymbol = syscallOldEnterKprobeAddress
	}

	es, err := s.registerKprobe(kprobeSymbol, false,
		syscallEnterKprobeFetchargs, s.decodeSyscallTraceEnter,
		filter, syscallEnterEventTypes)
	if major >= 3 {
		if err != nil {
			eventID = s.sensor.dummySyscallEventID
			if atomic.AddInt64(&s.sensor.dummySyscallEventCount, -1) == 0 {
				s.sensor.Monitor.UnregisterEvent(eventID)
			}
		} else {
			es.unregister = func(es *eventSink) {
				eventID = s.sensor.dummySyscallEventID
				if atomic.AddInt64(&s.sensor.dummySyscallEventCount, -1) == 0 {
					s.sensor.Monitor.UnregisterEvent(eventID)
				}
			}
		}
	}
}

// RegisterSyscallExitEventFilter registers a syscall exit event filter with a
// subscription.
func (s *Subscription) RegisterSyscallExitEventFilter(
	filter *expression.Expression,
) {
	syscallOnce.Do(s.initSyscallNames)

	s.registerTracepoint(syscallExitName, s.decodeSysExit,
		filter, syscallExitEventTypes)
}
