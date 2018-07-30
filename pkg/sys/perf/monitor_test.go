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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/proc"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"

	"golang.org/x/sys/unix"
)

type testProcFileSystem struct{}

func newTestProcFileSystem() proc.FileSystem {
	return &testProcFileSystem{}
}

func (fs *testProcFileSystem) BootID() string                  { return "bootid" }
func (fs *testProcFileSystem) MaxPID() uint                    { return 32768 }
func (fs *testProcFileSystem) NumCPU() int                     { return 2 }
func (fs *testProcFileSystem) Mounts() []proc.Mount            { return nil }
func (fs *testProcFileSystem) HostFileSystem() proc.FileSystem { return fs }
func (fs *testProcFileSystem) PerfEventDir() string            { return "" }
func (fs *testProcFileSystem) TracingDir() string              { return "testdata" }

func (fs *testProcFileSystem) KernelTextSymbolNames() (map[string]string, error) {
	return nil, unix.ENOSYS
}

func (fs *testProcFileSystem) ProcessContainerID(pid int) (string, error) {
	return "", unix.ESRCH
}

func (fs *testProcFileSystem) ProcessCommandLine(pid int) ([]string, error) {
	return nil, unix.ESRCH
}

func (fs *testProcFileSystem) TaskControlGroups(tigd, pid int) ([]proc.ControlGroup, error) {
	return nil, unix.ESRCH
}

func (fs *testProcFileSystem) TaskCWD(tgid, pid int) (string, error) {
	return "", unix.ESRCH
}

func (fs *testProcFileSystem) TaskStartTime(tgid, pid int) (int64, error) {
	return 0, unix.ESRCH
}

func (fs *testProcFileSystem) TaskUniqueID(tgid, pid int, startTime int64) (string, error) {
	return fmt.Sprintf("%d-%d-%d", tgid, pid, startTime), nil
}

func (fs *testProcFileSystem) WalkTasks(walkFunc proc.TaskWalkFunc) error {
	return nil
}

func (fs *testProcFileSystem) ReadTaskStatus(tgid, pid int, i interface{}) error {
	return unix.ESRCH
}

func TestEventMonitorOptions(t *testing.T) {
	expOptions := newEventMonitorOptions()
	expOptions.eventSourceController = NewStubEventSourceController()
	expOptions.flags = 827634
	expOptions.defaultEventAttr = &EventAttr{}
	expOptions.perfEventDir = "*** perf_event_dir ***"
	expOptions.tracingDir = "*** tracing_dir ***"
	expOptions.ringBufferNumPages = 88
	expOptions.cgroups = []string{"docker", "kubernetes", "capsule8"}
	expOptions.pids = []int{123, 456, 789}

	var err error
	expOptions.procfs, err = procfs.NewFileSystem("../proc/procfs/testdata/proc")
	ok(t, err)

	options := []EventMonitorOption{
		WithFlags(expOptions.flags),
		WithDefaultEventAttr(expOptions.defaultEventAttr),
		WithEventSourceController(expOptions.eventSourceController),
		WithProcFileSystem(expOptions.procfs),
		WithPerfEventDir(expOptions.perfEventDir),
		WithTracingDir(expOptions.tracingDir),
		WithRingBufferNumPages(expOptions.ringBufferNumPages),
		WithCgroups(expOptions.cgroups),
		WithCgroup("extra"),
		WithPids(expOptions.pids),
		WithPid(-1),
	}
	expOptions.cgroups = append(expOptions.cgroups, "extra")
	expOptions.pids = append(expOptions.pids, -1)

	gotOptions := eventMonitorOptions{}
	gotOptions.processOptions(options...)
	equals(t, expOptions, gotOptions)
}

func TestRegisterEventOptions(t *testing.T) {
	expOptions := newRegisterEventOptions()
	expOptions.disabled = true
	expOptions.eventAttr = &EventAttr{}
	expOptions.filter = "*** filter string ***"
	expOptions.groupID = 88888
	expOptions.name = "nnAAmmEE"

	options := []RegisterEventOption{
		WithEventDisabled(),
		WithEventAttr(expOptions.eventAttr),
		WithFilter(expOptions.filter),
		WithEventGroup(expOptions.groupID),
		WithTracingEventName(expOptions.name),
	}

	gotOptions := registerEventOptions{}
	gotOptions.processOptions(options...)
	equals(t, expOptions, gotOptions)

	expOptions.disabled = false
	gotOptions.processOptions(WithEventEnabled())
	equals(t, expOptions, gotOptions)
}

func TestEventTypeMappings(t *testing.T) {
	fromPerfTypes := map[uint32]EventType{
		PERF_TYPE_BREAKPOINT: EventTypeBreakpoint,
		PERF_TYPE_HARDWARE:   EventTypeHardware,
		PERF_TYPE_HW_CACHE:   EventTypeHardwareCache,
		PERF_TYPE_RAW:        EventTypeRaw,
		PERF_TYPE_SOFTWARE:   EventTypeSoftware,
		PERF_TYPE_TRACEPOINT: EventTypeTracepoint,
	}
	for pt, expET := range fromPerfTypes {
		gotET := eventTypeFromPerfType(pt)
		assert(t, expET == gotET, "mismatch PERF_TYPE_ %d", pt)
	}

	fromEventTypes := map[EventType]uint32{
		EventTypeTracepoint:    PERF_TYPE_TRACEPOINT,
		EventTypeKprobe:        PERF_TYPE_TRACEPOINT,
		EventTypeUprobe:        PERF_TYPE_TRACEPOINT,
		EventTypeHardware:      PERF_TYPE_HARDWARE,
		EventTypeSoftware:      PERF_TYPE_SOFTWARE,
		EventTypeHardwareCache: PERF_TYPE_HW_CACHE,
		EventTypeRaw:           PERF_TYPE_RAW,
		EventTypeBreakpoint:    PERF_TYPE_BREAKPOINT,
		// EventTypeDynamicPMU does not map
		// EventTypeExternal does not map
	}
	for et, expPT := range fromEventTypes {
		gotPT := perfTypeFromEventType(et)
		assert(t, expPT == gotPT, "mismatch %s", EventTypeNames[et])
	}
}

func TestUnboxNil(t *testing.T) {
	equals(t, nil, unboxNil(nil))
	equals(t, nil, unboxNil(([]int32)(nil)))
	equals(t, 888, unboxNil(888))
	equals(t, "capsule8", unboxNil("capsule8"))
}

func TestExternalEventSampleDecoder(t *testing.T) {
	d := externalEventSampleDecoder{}
	d.decoderFn = func(sample *SampleRecord, data TraceEventSampleData) (interface{}, error) {
		return "capsule8", nil
	}

	esm := EventMonitorSample{
		RawSample: Sample{Record: (*SampleRecord)(nil)},
	}
	d.decodeSample(&esm, nil)
	ok(t, esm.Err)
	equals(t, esm.DecodedSample, "capsule8")
}

func TestCounterEventSampleDecoder(t *testing.T) {
	type testCase struct {
		timeEnabled uint64
		timeRunning uint64
		counters    []CounterEventValue
	}
	var exp, got testCase

	d := counterEventSampleDecoder{}
	d.decoderFn = func(sample *SampleRecord, counters []CounterEventValue, timeEnabled, timeRunning uint64) (interface{}, error) {
		got = testCase{
			timeEnabled: timeEnabled,
			timeRunning: timeRunning,
			counters:    counters,
		}
		return got, nil
	}

	exp = testCase{
		timeEnabled: 29384756,
		timeRunning: 12039487,
		counters: []CounterEventValue{
			CounterEventValue{
				EventType: EventTypeHardware,
				Config:    PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
				Value:     234568,
			},
			CounterEventValue{
				EventType: EventTypeHardwareCache,
				Config:    PERF_COUNT_HW_CACHE_MISSES,
				Value:     345789329,
			},
		},
	}

	attrMap := newEventAttrMap()
	V := CounterGroup{
		TimeEnabled: exp.timeEnabled,
		TimeRunning: exp.timeRunning,
	}
	for i, c := range exp.counters {
		attrMap[uint64(i)] = EventAttr{
			Type:   perfTypeFromEventType(c.EventType),
			Config: c.Config,
		}
		v := CounterValue{
			ID:    uint64(i),
			Value: c.Value,
		}
		V.Values = append(V.Values, v)
	}

	esm := EventMonitorSample{
		RawSample: Sample{
			Record: &SampleRecord{
				V: V,
			},
		},
	}

	monitor := &EventMonitor{
		eventAttrMap: newSafeEventAttrMap(),
	}
	monitor.eventAttrMap.updateInPlace(attrMap)

	d.decodeSample(&esm, monitor)
	ok(t, esm.Err)
	equals(t, exp, got)
}

func TestTraceEventSampleDecoder(t *testing.T) {
	monitor := &EventMonitor{
		decoders:   newTraceEventDecoderMap("testdata"),
		tracingDir: "testdata/events/valid",
	}

	expDecodedSample := "capsule8"
	expDecodedData := TraceEventSampleData{
		"common_type":          uint16(78),
		"common_flags":         uint8(0x88),
		"common_preempt_count": uint8(0x23),
		"common_pid":           int32(0x44332211),
		"pid":                  int32(0x11223344),
	}

	fn := func(sample *SampleRecord, data TraceEventSampleData) (interface{}, error) {
		return expDecodedSample, nil
	}
	_, err := monitor.decoders.AddDecoder("valid/valid2", fn)
	ok(t, err)

	rawData := []byte{
		0x4e, 0x00, // common_type
		0x88,                   // common_flags
		0x23,                   // common_preempt_count
		0x11, 0x22, 0x33, 0x44, // common_pid
		0x44, 0x33, 0x22, 0x11, // pid
	}

	esm := EventMonitorSample{
		RawSample: Sample{
			Record: &SampleRecord{
				RawData: rawData,
			},
		},
	}

	d := traceEventSampleDecoder{}
	d.decodeSample(&esm, monitor)
	ok(t, esm.Err)
	equals(t, expDecodedSample, esm.DecodedSample)
	equals(t, expDecodedData, esm.DecodedData)
}

func TestPerfGroupLeader(t *testing.T) {
	pgl := perfGroupLeader{
		source: newStubEventSourceLeader(EventAttr{}, -1, 0),
		state:  perfGroupLeaderStateClosing,
	}
	pgl.cleanup()
	equals(t, pgl.state, perfGroupLeaderStateClosed)
}

func TestEventMonitorGroup(t *testing.T) {
	firstEventID := uint64(2934678)
	attr := EventAttr{
		Type:     PERF_TYPE_SOFTWARE,
		Config:   927834,
		Disabled: true}

	for x := 0; x < 2; x++ {
		monitor := &EventMonitor{
			nextEventID:  firstEventID,
			events:       newSafeRegisteredEventMap(),
			eventAttrMap: newSafeEventAttrMap(),
			eventIDMap:   newSafeUInt64Map(),
		}
		monitor.isRunning.Store(x == 1)

		var name string
		if monitor.isRunning.Load().(bool) {
			name = "unit test (running)"
		} else {
			name = "unit test"
		}

		leaders := []*StubEventSourceLeader{
			newStubEventSourceLeader(attr, -1, 0),
			newStubEventSourceLeader(attr, -1, 1),
		}
		group := &eventMonitorGroup{
			name: name,
			leaders: []*perfGroupLeader{
				&perfGroupLeader{
					source: leaders[0],
					state:  perfGroupLeaderStateActive,
				},
				&perfGroupLeader{
					source: leaders[1],
					state:  perfGroupLeaderStateActive,
				},
			},
			events:  make(map[uint64]*registeredEvent),
			monitor: monitor,
		}

		// Test: group.perfEventOpen
		expFilter := "this is a nonsense filter string"
		sources, err := group.perfEventOpen(name, attr, expFilter, 0)
		ok(t, err)
		assert(t, sources != nil, "perfEventOpen unexpectedly returned nil")
		equals(t, len(leaders), len(sources))
		for _, source := range sources {
			equals(t, expFilter, source.(*StubEventSource).Filter)
		}

		id := monitor.newRegisteredEvent(name, sources, nil,
			EventTypeSoftware, nil, attr, group, false)
		equals(t, firstEventID, id)
		equals(t, len(leaders), len(monitor.eventAttrMap.getMap()))
		equals(t, len(leaders), len(monitor.eventIDMap.getMap()))
		equals(t, 1, len(group.events))
		equals(t, 1, len(monitor.events.getMap()))

		expFilter = "This is a different nonsense filter string"
		err = monitor.SetFilter(id, expFilter)
		ok(t, err)
		for _, source := range sources {
			equals(t, expFilter, source.(*StubEventSource).Filter)
		}

		// Test: group.enable
		group.enable()
		equals(t, true, sources[0].(*StubEventSource).Enabled)
		equals(t, true, sources[1].(*StubEventSource).Enabled)
		equals(t, 1, sources[0].(*StubEventSource).EnableCount)
		equals(t, 1, sources[1].(*StubEventSource).EnableCount)

		// Test: group.disable
		group.disable()
		equals(t, false, sources[0].(*StubEventSource).Enabled)
		equals(t, false, sources[0].(*StubEventSource).Enabled)
		equals(t, 1, sources[0].(*StubEventSource).DisableCount)
		equals(t, 1, sources[1].(*StubEventSource).DisableCount)

		// Test: group.cleanup
		group.cleanup()
		equals(t, 0, len(monitor.eventAttrMap.getMap()))
		equals(t, 0, len(monitor.eventIDMap.getMap()))
		equals(t, 0, len(group.events))
		equals(t, 0, len(monitor.events.getMap()))
	}
}

func createTempTracingDir() (string, error) {
	tracingDir, err := ioutil.TempDir("", "capsule8_")
	if err != nil {
		return "", err
	}

	kprobeEvents := filepath.Join(tracingDir, "kprobe_events")
	if err = ioutil.WriteFile(kprobeEvents, []byte{}, 0666); err != nil {
		return tracingDir, err
	}

	uprobeEvents := filepath.Join(tracingDir, "uprobe_events")
	if err = ioutil.WriteFile(uprobeEvents, []byte{}, 0666); err != nil {
		return tracingDir, err
	}

	return tracingDir, nil
}

func TestTraceCommands(t *testing.T) {
	tracingDir, err := createTempTracingDir()
	if tracingDir != "" {
		defer os.RemoveAll(tracingDir)
	}
	ok(t, err)

	kprobeEvents := filepath.Join(tracingDir, "kprobe_events")
	uprobeEvents := filepath.Join(tracingDir, "uprobe_events")

	monitor := &EventMonitor{
		tracingDir: tracingDir,
	}

	// writeTraceCommand opens append only, so the file needs to be created
	// first
	rawTestFilename := filepath.Join(tracingDir, "raw_test")
	err = ioutil.WriteFile(rawTestFilename, []byte{}, 0666)
	ok(t, err)

	exp := "oodles of fun!"
	err = monitor.writeTraceCommand("raw_test", exp)
	ok(t, err)
	got, err := ioutil.ReadFile(rawTestFilename)
	ok(t, err)
	equals(t, exp, string(got))

	kprobeTestCases := []struct {
		name     string
		address  string
		onReturn bool
		output   string
		expected string
	}{
		{"group/kprobe_name_1", "address", false, "arg1=%ax:u64     arg2=%bx:s32   ",
			"p:group/kprobe_name_1 address arg1=%ax:u64 arg2=%bx:s32",
		},
		{"group/kretprobe_name_2", "asdfasdf", true, "r=%retval:u64",
			"r:group/kretprobe_name_2 asdfasdf r=%retval:u64",
		},
	}
	for _, tc := range kprobeTestCases {
		err = os.Truncate(kprobeEvents, 0)
		ok(t, err)

		err = monitor.addKprobe(tc.name, tc.address, tc.onReturn, tc.output)
		ok(t, err)
		got, err = ioutil.ReadFile(kprobeEvents)
		ok(t, err)
		equals(t, tc.expected, string(got))
	}

	err = os.Truncate(kprobeEvents, 0)
	ok(t, err)

	err = monitor.removeKprobe("foo/bar")
	ok(t, err)
	got, err = ioutil.ReadFile(kprobeEvents)
	ok(t, err)
	equals(t, "-:foo/bar", string(got))

	uprobeTestCases := []struct {
		name     string
		bin      string
		address  string
		onReturn bool
		output   string
		expected string
	}{
		{"group/uprobe_name_1", "/bin/sh", "address", false,
			"arg1=%ax:u64     arg2=%bx:s32   ",
			"p:group/uprobe_name_1 /bin/sh:address arg1=%ax:u64 arg2=%bx:s32",
		},
		{"group/uretprobe_name_2", "/bin/ls", "asdfasdf", true,
			"r=%retval:u64",
			"r:group/uretprobe_name_2 /bin/ls:asdfasdf r=%retval:u64",
		},
	}
	for _, tc := range uprobeTestCases {
		err = os.Truncate(uprobeEvents, 0)
		ok(t, err)

		err = monitor.addUprobe(tc.name, tc.bin, tc.address, tc.onReturn, tc.output)
		ok(t, err)
		got, err = ioutil.ReadFile(uprobeEvents)
		ok(t, err)
		equals(t, tc.expected, string(got))
	}

	err = os.Truncate(uprobeEvents, 0)
	ok(t, err)

	err = monitor.removeUprobe("foo/bar")
	ok(t, err)
	got, err = ioutil.ReadFile(uprobeEvents)
	ok(t, err)
	equals(t, "-:foo/bar", string(got))
}

func TestEventGroupRegistration(t *testing.T) {
	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir("testdata"),
		WithPid(234),
		WithPid(234))
	ok(t, err)
	equals(t, 1, len(monitor.groups))

	defer func() {
		monitor.isRunning.Store(false)
		monitor.Close()
	}()

	err = monitor.EnableGroup(867)
	assert(t, err != nil, "Unexpected nil return for EnableGroup(867)")

	err = monitor.DisableGroup(867)
	assert(t, err != nil, "Unexpected nil return for DisableGroup(867)")

	err = monitor.UnregisterEventGroup(867)
	assert(t, err != nil, "Unexpected nil return for UnregisterEventGroup(867)")

	for x := 0; x < 2; x++ {
		monitor.isRunning.Store(x == 1)

		id, err := monitor.RegisterEventGroup("")
		ok(t, err)
		equals(t, int32(x+1), id)
		equals(t, 2, len(monitor.groups))

		err = monitor.EnableGroup(id)
		ok(t, err)

		err = monitor.DisableGroup(id)
		ok(t, err)

		err = monitor.UnregisterEventGroup(id)
		ok(t, err)
		equals(t, 1, len(monitor.groups))
	}
}

func TestEventManipulation(t *testing.T) {
	tracingDir, err := createTempTracingDir()
	if tracingDir != "" {
		defer os.RemoveAll(tracingDir)
	}
	ok(t, err)

	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir(tracingDir))
	ok(t, err)
	defer monitor.Close()

	eventTypes := []EventType{
		EventTypeBreakpoint, EventTypeHardware,
		EventTypeHardwareCache, EventTypeKprobe, EventTypeRaw,
		EventTypeSoftware, EventTypeTracepoint, EventTypeUprobe,
	}
	ids := make([]uint64, len(eventTypes))
	for x, eventType := range eventTypes {
		fields := map[string]int32{
			EventTypeNames[eventType]: int32(x),
		}
		var eventid uint64
		eventid, err = monitor.newRegisteredPerfEvent(
			EventTypeNames[eventType], uint64(x),
			fields, registerEventOptions{disabled: true},
			eventType, nil)
		ok(t, err)
		equals(t, x+1, len(monitor.events.getMap()))
		e, ok := monitor.events.lookup(eventid)
		equals(t, true, ok)
		equals(t, eventid, e.id)
		equals(t, eventType, e.eventType)
		ids[x] = eventid
	}

	for x, eventid := range ids {
		eventType, ok := monitor.RegisteredEventType(eventid)
		equals(t, true, ok)
		equals(t, eventTypes[x], eventType)

		expectedFields := map[string]int32{
			EventTypeNames[eventType]: int32(x),
		}
		fields := monitor.RegisteredEventFields(eventid)
		assert(t, fields != nil, "unexpected nil return from RegisteredEventFields")
		equals(t, expectedFields, fields)

		monitor.Enable(eventid)
		e, ok := monitor.events.lookup(eventid)
		equals(t, true, ok)
		for _, source := range e.sources {
			equals(t, true, source.(*StubEventSource).Enabled)
			equals(t, 1, source.(*StubEventSource).EnableCount)
		}

		monitor.Disable(eventid)
		e, ok = monitor.events.lookup(eventid)
		equals(t, true, ok)
		for _, source := range e.sources {
			equals(t, false, source.(*StubEventSource).Enabled)
			equals(t, 1, source.(*StubEventSource).DisableCount)
		}
	}

	monitor.EnableAll()
	for _, eventid := range ids {
		e, ok := monitor.events.lookup(eventid)
		equals(t, true, ok)
		for _, source := range e.sources {
			equals(t, true, source.(*StubEventSource).Enabled)
			equals(t, 2, source.(*StubEventSource).EnableCount)
		}
	}

	monitor.DisableAll()
	for _, eventid := range ids {
		e, ok := monitor.events.lookup(eventid)
		equals(t, true, ok)
		for _, source := range e.sources {
			equals(t, false, source.(*StubEventSource).Enabled)
			equals(t, 2, source.(*StubEventSource).DisableCount)
		}
	}

	for _, eventid := range ids {
		monitor.UnregisterEvent(eventid)
	}
	equals(t, 0, len(monitor.events.getMap()))

	opts := registerEventOptions{
		eventAttr: &EventAttr{},
		groupID:   937854,
	}
	_, err = monitor.newRegisteredPerfEvent("non-existent group",
		12345, nil, opts, EventTypeTracepoint, nil)
	assert(t, err != nil, "this should error with non-existent group error")

	eventType, ok := monitor.RegisteredEventType(234987)
	assert(t, !ok, "ok should be false")
	equals(t, EventTypeInvalid, eventType)

	fields := monitor.RegisteredEventFields(23434978)
	equals(t, (map[string]int32)(nil), fields)

	err = monitor.UnregisterEvent(298374)
	assert(t, err != nil, "err should be non-nil")
}

func TestNewRegisteredTraceEvent(t *testing.T) {
	tracingDir, err := createTempTracingDir()
	if tracingDir != "" {
		defer os.RemoveAll(tracingDir)
	}
	ok(t, err)

	eventDir := filepath.Join(tracingDir, "events", "task", "task_newtask")
	err = os.MkdirAll(eventDir, 0777)
	ok(t, err)

	formatContent := `name: task_newtask
ID: 109
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:pid_t pid;	offset:8;	size:4;	signed:1;
	field:char comm[16];	offset:12;	size:16;	signed:1;
	field:unsigned long clone_flags;	offset:32;	size:8;	signed:0;
	field:short oom_score_adj;	offset:40;	size:2;	signed:1;

print fmt: "pid=%d comm=%s clone_flags=%lx oom_score_adj=%hd", REC->pid, REC->comm, REC->clone_flags, REC->oom_score_adj`
	formatFile := filepath.Join(eventDir, "format")
	err = ioutil.WriteFile(formatFile, []byte(formatContent), 0666)
	ok(t, err)

	names := []string{"1", "2", "foo"}
	for _, name := range names {
		probeName := fmt.Sprintf("capsule8/sensor_%d_%s", unix.Getpid(), name)
		eventDir = filepath.Join(tracingDir, "events", probeName)
		err = os.MkdirAll(eventDir, 0777)
		ok(t, err)

		formatFile = filepath.Join(eventDir, "format")
		err = ioutil.WriteFile(formatFile, []byte(formatContent), 0666)
		ok(t, err)
	}

	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir(tracingDir))
	ok(t, err)
	defer monitor.Close()

	eventid, err := monitor.newRegisteredTraceEvent("task/task_newtask",
		nil, registerEventOptions{}, EventTypeTracepoint)
	ok(t, err)
	equals(t, 1, len(monitor.events.getMap()))
	e, found := monitor.events.lookup(eventid)
	equals(t, true, found)
	equals(t, eventid, e.id)
	equals(t, EventTypeTracepoint, e.eventType)

	err = monitor.UnregisterEvent(eventid)
	ok(t, err)
	equals(t, 0, len(monitor.events.getMap()))

	eventid, err = monitor.RegisterTracepoint("task/task_newtask", nil)
	ok(t, err)
	equals(t, 1, len(monitor.events.getMap()))
	e, found = monitor.events.lookup(eventid)
	equals(t, true, found)
	equals(t, eventid, e.id)
	equals(t, EventTypeTracepoint, e.eventType)

	err = monitor.UnregisterEvent(eventid)
	ok(t, err)
	equals(t, 0, len(monitor.events.getMap()))

	eventid, err = monitor.RegisterKprobe("address", false, "output", nil)
	ok(t, err)
	equals(t, 1, len(monitor.events.getMap()))
	e, found = monitor.events.lookup(eventid)
	equals(t, true, found)
	equals(t, eventid, e.id)
	equals(t, EventTypeKprobe, e.eventType)

	err = monitor.UnregisterEvent(eventid)
	ok(t, err)
	equals(t, 0, len(monitor.events.getMap()))

	eventid, err = monitor.RegisterKprobe("address", false, "output", nil,
		WithTracingEventName("foo"))
	ok(t, err)
	equals(t, 1, len(monitor.events.getMap()))
	e, found = monitor.events.lookup(eventid)
	equals(t, true, found)
	equals(t, eventid, e.id)
	equals(t, EventTypeKprobe, e.eventType)

	err = monitor.UnregisterEvent(eventid)
	ok(t, err)
	equals(t, 0, len(monitor.events.getMap()))

	eventid, err = monitor.RegisterUprobe("testdata/uprobe_test",
		"some_function", false, "string=+0(%di):string", nil)
	ok(t, err)
	equals(t, 1, len(monitor.events.getMap()))
	e, found = monitor.events.lookup(eventid)
	equals(t, true, found)
	equals(t, eventid, e.id)
	equals(t, EventTypeUprobe, e.eventType)

	err = monitor.UnregisterEvent(eventid)
	ok(t, err)
	equals(t, 0, len(monitor.events.getMap()))

	eventid, err = monitor.RegisterUprobe("testdata/uprobe_test",
		"some_function", false, "string=+0(%di):string", nil,
		WithTracingEventName("foo"))
	ok(t, err)
	equals(t, 1, len(monitor.events.getMap()))
	e, found = monitor.events.lookup(eventid)
	equals(t, true, found)
	equals(t, eventid, e.id)
	equals(t, EventTypeUprobe, e.eventType)

	err = monitor.UnregisterEvent(eventid)
	ok(t, err)
	equals(t, 0, len(monitor.events.getMap()))
}

func TestRegisterExternalEvent(t *testing.T) {
	tracingDir, err := createTempTracingDir()
	if tracingDir != "" {
		defer os.RemoveAll(tracingDir)
	}
	ok(t, err)

	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir(tracingDir))
	ok(t, err)
	defer monitor.Close()

	eventid := monitor.RegisterExternalEvent("dummy test", nil)
	equals(t, 1, len(monitor.events.getMap()))
	e, ok := monitor.events.lookup(eventid)
	equals(t, true, ok)
	equals(t, eventid, e.id)
	equals(t, EventTypeExternal, e.eventType)
}

func TestRegisterCounterEventGroup(t *testing.T) {
	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir("testdata"))
	ok(t, err)
	defer monitor.Close()

	_, _, err = monitor.RegisterCounterEventGroup("name", nil, nil)
	assert(t, err != nil, "len(counters) must be > 0")

	badMember := CounterEventGroupMember{EventType: EventType(23094572345)}
	_, _, err = monitor.RegisterCounterEventGroup("name",
		[]CounterEventGroupMember{badMember}, nil)
	assert(t, err != nil, "invalid EventType")

	var counters []CounterEventGroupMember
	_, _, err = monitor.RegisterCounterEventGroup("name", counters, nil)
	assert(t, err != nil, "len(counters) must be > 0")

	counters = append(counters,
		CounterEventGroupMember{EventType: EventTypeHardware})
	counters = append(counters,
		CounterEventGroupMember{EventType: EventTypeHardwareCache})
	counters = append(counters,
		CounterEventGroupMember{EventType: EventTypeSoftware})

	_, _, err = monitor.RegisterCounterEventGroup("name", counters, nil,
		WithFilter("bad filter"))
	assert(t, err != nil, "filters not valid for counter events")

	_, _, err = monitor.RegisterCounterEventGroup("name", counters, nil,
		WithEventGroup(234))
	assert(t, err != nil, "group must be 0")

	groupid, eventid, err := monitor.RegisterCounterEventGroup("name", counters, nil)
	ok(t, err)
	equals(t, int32(1), groupid)
	equals(t, uint64(1), eventid)
	equals(t, 3, len(monitor.events.getMap()))
	equals(t, 2, len(monitor.groups))
}

func TestMonitorRunStop(t *testing.T) {
	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir("testdata"))
	ok(t, err)
	defer monitor.Close()

	go monitor.Run(func(samples []EventMonitorSample) {
		t.Fatal("Unexpected event received")
	})
	time.Sleep(200 * time.Millisecond)

	err = monitor.Run(nil)
	assert(t, err != nil, "Second call to Run unexpectedly succeeded")
}

func TestExternalSampleList(t *testing.T) {
	var samples externalSampleList

	samples = append(samples, EventMonitorSample{
		RawSample: Sample{SampleID: SampleID{Time: 38945}},
	})
	samples = append(samples, EventMonitorSample{
		RawSample: Sample{SampleID: SampleID{Time: 827564}},
	})
	samples = append(samples, EventMonitorSample{
		RawSample: Sample{SampleID: SampleID{Time: 872643}},
	})

	// Samples should be sorted descending by time
	expected := externalSampleList{
		samples[2], samples[1], samples[0],
	}
	sort.Sort(samples)
	equals(t, expected, samples)
}

func TestSampleMerger(t *testing.T) {
	samples := [][]EventMonitorSample{
		[]EventMonitorSample{
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 10}}},
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 20}}},
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 30}}},
		},
		[]EventMonitorSample{
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 15}}},
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 25}}},
		},
		[]EventMonitorSample{
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 40}}},
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 50}}},
		},
		[]EventMonitorSample{
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 12}}},
			EventMonitorSample{RawSample: Sample{SampleID: SampleID{Time: 42}}},
		},
	}
	merger := newSampleMerger(samples)

	expected := []uint64{10, 12, 15, 20, 25, 30, 40, 42, 50}
	got := make([]uint64, 0, len(expected))
	for {
		if sample, done := merger.next(); !done {
			got = append(got, sample.RawSample.Time)
		} else {
			break
		}
	}

	equals(t, expected, got)
}

func TestEnqueueExternalSample(t *testing.T) {
	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir("testdata"))
	ok(t, err)
	defer monitor.Close()

	err = monitor.EnqueueExternalSample(29378, SampleID{}, nil)
	assert(t, err != nil, "expected non-nil for unregistered EventID")

	eventid, err := monitor.RegisterTracepoint("valid/valid", nil)
	ok(t, err)

	err = monitor.EnqueueExternalSample(eventid, SampleID{}, nil)
	assert(t, err != nil, "expected non-nil for non-external EventID")

	err = monitor.UnregisterEvent(eventid)
	ok(t, err)

	eventid = monitor.RegisterExternalEvent("external event",
		func(sample *SampleRecord, data TraceEventSampleData) (interface{}, error) {
			return sample, nil
		})

	err = monitor.EnqueueExternalSample(eventid, SampleID{}, nil)
	assert(t, err != nil, "expected non-nil for bad sample time")

	received := 0
	go monitor.Run(func(samples []EventMonitorSample) {
		received++
	})

	time.Sleep(50 * time.Millisecond)

	sample := SampleID{Time: uint64(sys.CurrentMonotonicRaw())}
	err = monitor.EnqueueExternalSample(eventid, sample, nil)
	ok(t, err)

	sample = SampleID{Time: uint64(sys.CurrentMonotonicRaw() + int64(20*time.Second))}
	err = monitor.EnqueueExternalSample(eventid, sample, nil)
	ok(t, err)

	time.Sleep(200 * time.Millisecond)

	monitor.Stop(true)
	equals(t, 1, received)
}

func TestEnqueueSamples(t *testing.T) {
	monitor := EventMonitor{}

	// Ensure empty sample lists are safe
	monitor.enqueueSamples(nil)
	monitor.enqueueSamples([][]EventMonitorSample{})

	samples := monitor.dequeueSamples()
	equals(t, ([][]EventMonitorSample)(nil), samples)

	one := [][]EventMonitorSample{
		[]EventMonitorSample{
			EventMonitorSample{EventID: 1},
		},
	}
	monitor.enqueueSamples(one)
	samples = monitor.dequeueSamples()
	equals(t, one, samples)
	samples = monitor.dequeueSamples()
	equals(t, ([][]EventMonitorSample)(nil), samples)

	two := [][]EventMonitorSample{
		[]EventMonitorSample{
			EventMonitorSample{EventID: 2},
		},
	}
	monitor.enqueueSamples(one)
	monitor.enqueueSamples(two)
	samples = monitor.dequeueSamples()
	equals(t, one, samples)
	samples = monitor.dequeueSamples()
	equals(t, two, samples)
	samples = monitor.dequeueSamples()
	equals(t, ([][]EventMonitorSample)(nil), samples)
}

func TestSampleDispatch(t *testing.T) {
	monitor, err := NewEventMonitor(
		WithEventSourceController(NewStubEventSourceController()),
		WithProcFileSystem(newTestProcFileSystem()),
		WithTracingDir("testdata"))
	ok(t, err)
	defer monitor.Close()

	var gotTimes []uint64
	go monitor.Run(func(samples []EventMonitorSample) {
		for _, esm := range samples {
			gotTimes = append(gotTimes, esm.RawSample.Time)
		}
	})

	eventid, err := monitor.RegisterTracepoint("valid/valid2",
		func(sample *SampleRecord, data TraceEventSampleData) (interface{}, error) {
			return sample, nil
		})
	ok(t, err)
	event, ok := monitor.events.lookup(eventid)
	equals(t, true, ok)
	equals(t, 2, len(event.sources))

	// NumCPU is 2, so for the first source start with time 200. For the
	// second, use a time before and after so that pendingSamples code
	// paths are covered.

	rawData := []byte{
		0x4e, 0x00, // common_type
		0x00,                   // common_flags
		0x00,                   // common_preempt_count
		0x11, 0x22, 0x33, 0x44, // common_pid
		0x12, 0x34, 0x56, 0x78, // pid
	}

	sample := Sample{
		SampleID: SampleID{Time: 200, StreamID: event.sources[0].SourceID()},
		Record:   &SampleRecord{RawData: rawData},
	}
	event.group.leaders[0].source.(*StubEventSourceLeader).EnqueueSample(sample, nil)

	// This sample is intended to be invalid (invalid StreamID)
	sample = Sample{
		SampleID: SampleID{Time: 250, StreamID: 0},
		Record:   &SampleRecord{},
	}
	event.group.leaders[0].source.(*StubEventSourceLeader).EnqueueSample(sample, nil)

	sample = Sample{
		SampleID: SampleID{Time: 100, StreamID: event.sources[1].SourceID()},
		Record:   &SampleRecord{RawData: rawData},
	}
	event.group.leaders[1].source.(*StubEventSourceLeader).EnqueueSample(sample, nil)

	sample = Sample{
		SampleID: SampleID{Time: 300, StreamID: event.sources[1].SourceID()},
		Record:   &SampleRecord{RawData: rawData},
	}
	event.group.leaders[1].source.(*StubEventSourceLeader).EnqueueSample(sample, nil)

	// Encode a dummy external sample here to exercise those code paths
	monitor.lock.Lock()
	sample = Sample{SampleID: SampleID{Time: 150}}
	monitor.externalSamples = append(monitor.externalSamples,
		EventMonitorSample{EventID: 286743, RawSample: sample})
	monitor.lock.Unlock()

	monitor.eventSourceController.(*StubEventSourceController).Wakeup()
	time.Sleep(200 * time.Millisecond)

	monitor.Stop(true)

	expectedTimes := []uint64{100, 200, 300}
	equals(t, expectedTimes, gotTimes)
}
