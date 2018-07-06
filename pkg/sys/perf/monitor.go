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
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/proc"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"
	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

var (
	eventMonitorOnce sync.Once
	haveClockID      bool
	notedClockID     bool
	timeBase         int64
	timeOffsets      []int64
)

type eventMonitorOptions struct {
	procfs             proc.FileSystem
	flags              uintptr
	defaultEventAttr   *EventAttr
	perfEventDir       string
	tracingDir         string
	ringBufferNumPages int
	cgroups            []string
	pids               []int
}

// EventMonitorOption is used to implement optional arguments for
// NewEventMonitor. It must be exported, but it is not typically
// used directly.
type EventMonitorOption func(*eventMonitorOptions)

// WithFlags is used to set optional flags when creating a new EventMonitor.
// The flags are passed to the low-level perf_event_open() system call.
func WithFlags(flags uintptr) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.flags = flags
	}
}

// WithDefaultEventAttr is used to set an optional EventAttr struct to be used
// by default when registering events and no EventAttr is specified as part of
// the registration.
func WithDefaultEventAttr(defaultEventAttr *EventAttr) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.defaultEventAttr = defaultEventAttr
	}
}

// WithProcFileSystem is used to set the proc.FileSystem to use. The system
// default will be used if one is not specified.
func WithProcFileSystem(procfs proc.FileSystem) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.procfs = procfs
	}
}

// WithPerfEventDir is used to set an optional directory to use for monitoring
// cgroups. This should only be necessary if the perf_event cgroup fs is not
// mounted in the usual location.
func WithPerfEventDir(dir string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.perfEventDir = dir
	}
}

// WithTracingDir is used to set an alternate mountpoint to use for managing
// tracepoints, kprobes, and uprobes.
func WithTracingDir(dir string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.tracingDir = dir
	}
}

// WithRingBufferNumPages is used to set the size of the ringbuffers used to
// retrieve samples from the kernel.
func WithRingBufferNumPages(numPages int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.ringBufferNumPages = numPages
	}
}

// WithCgroup is used to add a cgroup to the set of sources to monitor.
func WithCgroup(cgroup string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.cgroups = append(o.cgroups, cgroup)
	}
}

// WithCgroups is used to add a list of cgroups to the set of sources to
// monitor.
func WithCgroups(cgroups []string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.cgroups = append(o.cgroups, cgroups...)
	}
}

// WithPid is used to add a pid to the set of sources to monitor.
func WithPid(pid int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.pids = append(o.pids, pid)
	}
}

// WithPids is used to add a list of pids to the set of sources to monitor.
func WithPids(pids []int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.pids = append(o.pids, pids...)
	}
}

type registerEventOptions struct {
	disabled  bool
	eventAttr *EventAttr
	filter    string
	groupID   int32
	decoderFn TraceEventDecoderFn
}

func processRegisterEventOptions(
	options ...RegisterEventOption,
) registerEventOptions {
	opts := registerEventOptions{
		disabled: true,
	}
	for _, option := range options {
		option(&opts)
	}
	return opts
}

// RegisterEventOption is used to implement optional arguments for event
// registration methods. It must be exported, but it is not typically used
// directly.
type RegisterEventOption func(*registerEventOptions)

// WithEventDisabled is used to register the event in a disabled state.
func WithEventDisabled() RegisterEventOption {
	return func(o *registerEventOptions) {
		o.disabled = true
	}
}

// WithEventEnabled is used to register the event in an enabled state.
func WithEventEnabled() RegisterEventOption {
	return func(o *registerEventOptions) {
		o.disabled = false
	}
}

// WithEventAttr is used to register the event with an EventAttr struct
// instead of using the EventMonitor's default.
func WithEventAttr(eventAttr *EventAttr) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.eventAttr = eventAttr
	}
}

// WithFilter is used to set a filter for the event.
func WithFilter(filter string) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.filter = filter
	}
}

// WithEventGroup is used to register the event to a specific event group.
func WithEventGroup(groupID int32) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.groupID = groupID
	}
}

// EventType represents the type of an event (tracepoint, external, etc.)
type EventType int

const (
	// EventTypeInvalid is not a valid event type
	EventTypeInvalid EventType = iota

	// EventTypeTracepoint is a trace event (PERF_TYPE_TRACEPOINT)
	EventTypeTracepoint

	// EventTypeKprobe is a kernel probe
	EventTypeKprobe
	// EventTypeUprobe is a user probe
	EventTypeUprobe

	// EventTypeHardware is a hardware event (PERF_TYPE_HARDWARE)
	EventTypeHardware

	// EventTypeSoftware is a software event (PERF_TYPE_SOFTWARE)
	EventTypeSoftware

	// EventTypeHardwareCache is a hardware cache event (PERF_TYPE_HW_CACHE)
	EventTypeHardwareCache

	// EventTypeRaw is a raw event (PERF_TYPE_RAW)
	EventTypeRaw

	// EventTypeBreakpoint is a breakpoint event (PERF_TYPE_BREAKPOINT)
	EventTypeBreakpoint

	// EventTypeDynamicPMU is a dynamic PMU event
	EventTypeDynamicPMU

	// EventTypeExternal is an external event
	EventTypeExternal
)

// EventTypeNames is a mapping of EventType to a human-readable string that is
// the name of the symbolic constant.
var EventTypeNames = map[EventType]string{
	EventTypeTracepoint:    "EventTypeTracepoint",
	EventTypeKprobe:        "EventTypeKprobe",
	EventTypeUprobe:        "EventTypeUprobe",
	EventTypeHardware:      "EventTypeHardware",
	EventTypeSoftware:      "EventTypeSoftware",
	EventTypeHardwareCache: "EventTypeHardwareCache",
	EventTypeRaw:           "EventTypeRaw",
	EventTypeBreakpoint:    "EventTypeBreakpoint",
	EventTypeDynamicPMU:    "EventTypeDynamicPMU",
	EventTypeExternal:      "EventTypeExternal",
}

func eventTypeFromPerfType(t uint32) EventType {
	switch t {
	case PERF_TYPE_HARDWARE:
		return EventTypeHardware
	case PERF_TYPE_HW_CACHE:
		return EventTypeHardwareCache
	case PERF_TYPE_SOFTWARE:
		return EventTypeSoftware
	case PERF_TYPE_BREAKPOINT:
		return EventTypeBreakpoint
	case PERF_TYPE_RAW:
		return EventTypeRaw
	case PERF_TYPE_TRACEPOINT:
		// Could be kprobe or uprobe, but not enough information to
		// make a determination
		return EventTypeTracepoint
	}
	glog.Fatalf("Unrecognized event type %d", t)
	return EventTypeInvalid
}

func perfTypeFromEventType(t EventType) uint32 {
	switch t {
	case EventTypeHardware:
		return PERF_TYPE_HARDWARE
	case EventTypeSoftware:
		return PERF_TYPE_SOFTWARE
	case EventTypeTracepoint, EventTypeKprobe, EventTypeUprobe:
		return PERF_TYPE_TRACEPOINT
	case EventTypeHardwareCache:
		return PERF_TYPE_HW_CACHE
	case EventTypeRaw:
		return PERF_TYPE_RAW
	case EventTypeBreakpoint:
		return PERF_TYPE_BREAKPOINT
	}
	glog.Fatalf("Unrecognized event type %d", t)
	return 0
}

type eventSampleDecoder interface {
	decodeSample(*EventMonitorSample, *EventMonitor)
}

type externalEventSampleDecoder struct {
	decoderFn TraceEventDecoderFn
}

func (d externalEventSampleDecoder) decodeSample(
	esm *EventMonitorSample,
	monitor *EventMonitor,
) {
	if d.decoderFn == nil {
		return
	}

	var s interface{}
	s, esm.Err = d.decoderFn(
		esm.RawSample.Record.(*SampleRecord),
		esm.DecodedData)

	// Yes. For maximum simplicity later, all of this nonsense is
	// necessary here.
	if s == nil {
		return
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return
		}
	}
	esm.DecodedSample = s
}

// CounterEventValue is a counter value returned from the kernel. The EventType
// and Config values are what were used to register the counter group member,
// and Value is the value returned with the sample.
type CounterEventValue struct {
	EventType EventType
	Config    uint64
	Value     uint64
}

// CounterEventDecoderFn is the signature of a function to call to decode a
// counter event sample. The first argument is the sample to be decoded, the
// second is a map of event counter IDs to values, the third is the total time
// the event has been enabled, and the fourth is the total time the event has
// been running.
type CounterEventDecoderFn func(*SampleRecord, []CounterEventValue, uint64, uint64) (interface{}, error)

type counterEventSampleDecoder struct {
	decoderFn CounterEventDecoderFn
}

func (d counterEventSampleDecoder) decodeSample(
	esm *EventMonitorSample,
	monitor *EventMonitor,
) {
	if d.decoderFn == nil {
		return
	}

	sample, ok := esm.RawSample.Record.(*SampleRecord)
	if !ok {
		return
	}

	attrMap := monitor.eventAttrMap.getMap()
	counters := make([]CounterEventValue, 0, len(sample.V.Values))
	for _, v := range sample.V.Values {
		var attr *EventAttr
		if attr, ok = attrMap[v.ID]; ok {
			counters = append(counters, CounterEventValue{
				EventType: eventTypeFromPerfType(attr.Type),
				Config:    attr.Config,
				Value:     v.Value,
			})
		}
	}

	var s interface{}
	s, esm.Err = d.decoderFn(sample, counters,
		sample.V.TimeEnabled, sample.V.TimeRunning)

	// Yes. For maximum simplicity later, all of this nonsense is
	// necessary here.
	if s == nil {
		return
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return
		}
	}
	esm.DecodedSample = s
}

type traceEventSampleDecoder struct {
}

func (d traceEventSampleDecoder) decodeSample(
	esm *EventMonitorSample,
	monitor *EventMonitor,
) {
	var s interface{}
	esm.DecodedData, s, esm.Err = monitor.decoders.DecodeSample(
		esm.RawSample.Record.(*SampleRecord))

	// Yes. For maximum simplicity later, all of this nonsense is
	// necessary here.
	if s == nil {
		return
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return
		}
	}
	esm.DecodedSample = s
}

type registeredEvent struct {
	id        uint64
	name      string
	fds       []int
	fields    map[string]int32
	decoder   eventSampleDecoder
	eventType EventType
	group     *eventMonitorGroup
	leader    bool
}

const (
	perfGroupLeaderStateActive = iota
	perfGroupLeaderStateClosing
	perfGroupLeaderStateClosed
)

type perfGroupLeader struct {
	rb    *ringBuffer
	pid   int     // passed as 'pid' argument to perf_event_open()
	cpu   int     // passed as 'cpu' argument to perf_event_open()
	flags uintptr // passed as 'flags' argument to perf_event_open()
	fd    int     // fd returned from perf_event_open()

	// This is the event's state. Normally it will be active. When a group
	// is being removed, it will transition to closing, which means that
	// the ringbuffer servicing goroutine should ignore it. That goroutine
	// will call .cleanup() for the event and transition it to the closed
	// state, which means that it can be safely removed by any goroutine at
	// any point in the future.
	state int32

	// Mutable only by the monitor goroutine while running. No
	// synchronization is required.
	pendingSamples []EventMonitorSample
}

func (pgl *perfGroupLeader) cleanup() {
	if pgl.rb != nil {
		pgl.rb.unmap()
		pgl.rb = nil
	}
	if pgl.fd != -1 {
		unix.Close(pgl.fd)
		pgl.fd = -1
	}
	atomic.StoreInt32(&pgl.state, perfGroupLeaderStateClosed)
}

type eventMonitorGroup struct {
	name    string
	leaders []*perfGroupLeader
	events  map[uint64]*registeredEvent
	monitor *EventMonitor
	groupID int32
}

func (group *eventMonitorGroup) cleanup() {
	// First we disable all events. This is necessary because of CentOS 6's
	// kernel bugs that could cause a kernel panic if we don't do this.
	group.disable()

	// Now we can unregister all of the events
	monitor := group.monitor
	for eventid, event := range group.events {
		if monitor.isRunning {
			monitor.events.remove(eventid)
		} else {
			monitor.events.removeInPlace(eventid)
		}
		monitor.removeRegisteredEvent(event)
	}
}

func (group *eventMonitorGroup) disable() {
	for _, event := range group.events {
		for _, fd := range event.fds {
			disable(fd)
		}
	}
}

func (group *eventMonitorGroup) enable() {
	for _, event := range group.events {
		for _, fd := range event.fds {
			enable(fd)
		}
	}
}

func (group *eventMonitorGroup) perfEventOpen(
	name string,
	eventAttr *EventAttr,
	filter string,
	flags uintptr,
) ([]int, error) {
	glog.V(2).Infof("Opening perf event: %s (%d) in group %d %q {%s}",
		name, eventAttr.Config, group.groupID, group.name, filter)

	var err error
	newfds := make([]int, 0, len(group.leaders))
	for _, pgl := range group.leaders {
		var fd int
		fd, err = open(eventAttr, pgl.pid, pgl.cpu, pgl.fd,
			pgl.flags|flags)
		if err != nil {
			break
		}
		newfds = append(newfds, fd)

		if len(filter) > 0 {
			err = setFilter(fd, filter)
			if err != nil {
				break
			}
		}
	}

	if err != nil {
		for j := len(newfds) - 1; j >= 0; j-- {
			unix.Close(newfds[j])
		}
		return nil, err
	}
	return newfds, nil
}

// SampleDispatchFn is the signature of a function called to dispatch samples.
// Samples are dispatched in batches as they become available.
type SampleDispatchFn func([]EventMonitorSample)

// EventMonitor is a high-level interface to the Linux kernel's perf_event
// infrastructure.
type EventMonitor struct {
	// Ordering of fields is intentional to keep the most frequently used
	// fields together at the head of the struct in an effort to increase
	// cache locality

	// Immutable items. No protection required. These fields are all set
	// when the EventMonitor is created and never changed after that.
	epollFD int

	// Mutable by various goroutines, and also needed by the monitor
	// goroutine. All of these are thread-safe mutable without a lock.
	// The monitor goroutine only ever reads from them, so there's no lock
	// taken. The thread-safe mutation of .decoders is handled elsewhere.
	// The other safe maps will lock if the monitor goroutine is running;
	// otherwise, .lock protects in-place writes.
	groupLeaders *safePerfGroupLeaderMap // fd : group leader data
	eventAttrMap *safeEventAttrMap       // stream id : event attr
	eventIDMap   *safeUInt64Map          // stream id : event id
	decoders     *traceEventDecoderMap
	events       *safeRegisteredEventMap // event id : event

	// Mutable only by the monitor goroutine while running. No protection
	// required.
	hasPendingSamples bool

	// Immutable once set. Only used by the dispatchSampleLoop goroutine.
	// Load once there and cache locally to avoid cache misses on this
	// struct.
	dispatchFn SampleDispatchFn

	// Used by dispatch
	dispatchQueueHead       *queuedSamples
	dispatchQueueTail       *queuedSamples
	dispatchFreeList        *queuedSamples
	dispatchExternalSamples bool

	// Mutable only by the dispatchSampleLoop goroutine. As external
	// samples are pulled from externalSamples, they're entered into this
	// list so that the mutex need not be locked for every single event
	// while pending externalSamples remain undispatched.
	pendingExternalSamples   externalSampleList
	lastSampleTimeDispatched uint64

	// This lock protects everything mutable below this point.
	lock sync.Mutex
	cond sync.Cond

	// Mutable only by the monitor goroutine, but readable by others
	isRunning bool
	pipe      [2]int

	// Mutable by various goroutines, but not required by the monitor goroutine
	nextEventID            uint64
	nextProbeID            uint64
	nextGroupID            int32
	groups                 map[int32]*eventMonitorGroup
	eventfds               map[int]int    // fd : cpu index
	eventids               map[int]uint64 // fd : stream id
	externalSamples        externalSampleList
	nextExternalSampleTime uint64

	// Immutable, used only when adding new tracepoints/probes
	defaultAttr EventAttr
	tracingDir  string
	procFS      proc.FileSystem

	// Immutable, used only when adding new groups
	ringBufferNumPages int
	perfEventOpenFlags uintptr
	cgroups            []int
	pids               []int

	// Used only once during shutdown
	wg sync.WaitGroup
}

type queuedSamples struct {
	next    *queuedSamples
	samples [][]EventMonitorSample
}

func fixupEventAttr(eventAttr *EventAttr) {
	// Adjust certain fields in eventAttr that must be set a certain way
	eventAttr.SampleType |= PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_TIME
	eventAttr.Disabled = true
	eventAttr.Pinned = false
	eventAttr.SampleIDAll = true

	if haveClockID {
		eventAttr.UseClockID = true
		eventAttr.ClockID = unix.CLOCK_MONOTONIC_RAW
	} else {
		eventAttr.UseClockID = false
		eventAttr.ClockID = 0
	}

	if eventAttr.Freq && eventAttr.SampleFreq == 0 {
		eventAttr.SampleFreq = 1
	} else if !eventAttr.Freq && eventAttr.SamplePeriod == 0 {
		eventAttr.SamplePeriod = 1
	}

	// Either WakeupWatermark or WakeupEvents may be used, but at least
	// one must be non-zero, because EventMonitor does not poll.
	if eventAttr.Watermark && eventAttr.WakeupWatermark == 0 {
		eventAttr.WakeupWatermark = 1
	} else if !eventAttr.Watermark && eventAttr.WakeupEvents == 0 {
		eventAttr.WakeupEvents = 1
	}
}

func (monitor *EventMonitor) writeTraceCommand(name string, cmd string) error {
	filename := filepath.Join(monitor.tracingDir, name)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		glog.Fatalf("Couldn't open %s WO+A: %s", filename, err)
	}
	defer file.Close()

	_, err = file.Write([]byte(cmd))
	return err
}

func normalizeFetchargs(args string) string {
	// Normalize the output string so we can match it later
	args = strings.TrimSpace(args)
	if strings.Index(args, "  ") != -1 {
		parts := strings.Split(args, " ")
		result := make([]string, 0, len(parts))
		for _, s := range parts {
			if len(s) > 0 {
				result = append(result, s)
			}
		}
		args = strings.Join(result, " ")
	}

	return args
}

func (monitor *EventMonitor) addKprobe(
	name string,
	address string,
	onReturn bool,
	output string,
) error {
	output = normalizeFetchargs(output)

	var definition string
	if onReturn {
		definition = fmt.Sprintf("r:%s %s %s", name, address, output)
	} else {
		definition = fmt.Sprintf("p:%s %s %s", name, address, output)
	}

	glog.V(1).Infof("Adding kprobe: '%s'", definition)
	return monitor.writeTraceCommand("kprobe_events", definition)
}

func (monitor *EventMonitor) removeKprobe(name string) error {
	return monitor.writeTraceCommand("kprobe_events",
		fmt.Sprintf("-:%s", name))
}

func (monitor *EventMonitor) addUprobe(
	name string,
	bin string,
	address string,
	onReturn bool,
	output string,
) error {
	output = normalizeFetchargs(output)

	var definition string
	if onReturn {
		definition = fmt.Sprintf("r:%s %s:%s %s", name, bin, address, output)
	} else {
		definition = fmt.Sprintf("p:%s %s:%s %s", name, bin, address, output)
	}

	glog.V(1).Infof("Adding uprobe: '%s'", definition)
	return monitor.writeTraceCommand("uprobe_events", definition)
}

func (monitor *EventMonitor) removeUprobe(name string) error {
	return monitor.writeTraceCommand("uprobe_events",
		fmt.Sprintf("-:%s", name))
}

func (monitor *EventMonitor) newProbeName() string {
	monitor.nextProbeID++
	return fmt.Sprintf("capsule8/sensor_%d_%d", unix.Getpid(),
		monitor.nextProbeID)
}

func (monitor *EventMonitor) newRegisteredEvent(
	name string,
	newfds []int,
	fields map[string]int32,
	eventType EventType,
	decoder eventSampleDecoder,
	attr *EventAttr,
	group *eventMonitorGroup,
	leader bool,
) (uint64, error) {
	// Choose the eventid for this event now, but don't commit to it until
	// later when no error has occurred in registering the event.
	eventid := monitor.nextEventID

	eventAttrMap := newEventAttrMap()
	eventIDMap := newUInt64Map()
	for _, fd := range newfds {
		streamid, err := unix.IoctlGetInt(fd, PERF_EVENT_IOC_ID)
		if err != nil {
			for _, fd := range newfds {
				delete(monitor.eventids, fd)
			}
			return 0, err
		}
		eventAttrMap[uint64(streamid)] = attr
		eventIDMap[uint64(streamid)] = eventid
		monitor.eventids[fd] = uint64(streamid)
	}

	// Now is the time to commit to the eventid
	monitor.nextEventID++
	if monitor.isRunning {
		monitor.eventAttrMap.update(eventAttrMap)
		monitor.eventIDMap.update(eventIDMap)
	} else {
		monitor.eventAttrMap.updateInPlace(eventAttrMap)
		monitor.eventIDMap.updateInPlace(eventIDMap)
	}
	for i, fd := range newfds {
		monitor.eventfds[fd] = i
	}

	event := &registeredEvent{
		id:        eventid,
		name:      name,
		fds:       newfds,
		fields:    fields,
		decoder:   decoder,
		eventType: eventType,
		group:     group,
		leader:    leader,
	}
	group.events[eventid] = event

	if monitor.isRunning {
		monitor.events.insert(eventid, event)
	} else {
		monitor.events.insertInPlace(eventid, event)
	}

	return eventid, nil
}

func (monitor *EventMonitor) newRegisteredPerfEvent(
	name string,
	config uint64,
	fields map[string]int32,
	opts registerEventOptions,
	eventType EventType,
	decoder eventSampleDecoder,
) (uint64, error) {
	// This should be called with monitor.lock held.

	var (
		attr  EventAttr
		flags uintptr
	)

	if opts.eventAttr == nil {
		attr = monitor.defaultAttr
	} else {
		attr = *opts.eventAttr
		fixupEventAttr(&attr)
	}
	attr.Config = config
	attr.Disabled = opts.disabled

	switch eventType {
	case EventTypeHardware:
		attr.Type = PERF_TYPE_HARDWARE
	case EventTypeSoftware:
		attr.Type = PERF_TYPE_SOFTWARE
	case EventTypeTracepoint, EventTypeKprobe, EventTypeUprobe:
		attr.Type = PERF_TYPE_TRACEPOINT
		flags = PERF_FLAG_FD_OUTPUT | PERF_FLAG_FD_NO_GROUP
	case EventTypeHardwareCache:
		attr.Type = PERF_TYPE_HW_CACHE
	case EventTypeRaw:
		attr.Type = PERF_TYPE_RAW
	case EventTypeBreakpoint:
		attr.Type = PERF_TYPE_BREAKPOINT
	}

	group, ok := monitor.groups[opts.groupID]
	if !ok {
		return 0, fmt.Errorf("Group ID %d does not exist", opts.groupID)
	}

	newfds, err := group.perfEventOpen(name, &attr, opts.filter, flags)
	if err != nil {
		return 0, err
	}

	eventid, err := monitor.newRegisteredEvent(name, newfds, fields,
		eventType, decoder, &attr, group, false)
	if err != nil {
		for _, fd := range newfds {
			unix.Close(fd)
		}
		return 0, err
	}
	return eventid, nil
}

func (monitor *EventMonitor) newRegisteredTraceEvent(
	name string,
	fn TraceEventDecoderFn,
	opts registerEventOptions,
	eventType EventType,
) (uint64, error) {
	// This should be called with monitor.lock held.

	id, err := monitor.decoders.AddDecoder(name, fn)
	if err != nil {
		return 0, err
	}

	decoder := monitor.decoders.getDecoder(id)
	fields := make(map[string]int32, len(decoder.fields))
	for k, v := range decoder.fields {
		fields[k] = v.dataType
	}

	eventid, err := monitor.newRegisteredPerfEvent(name, uint64(id),
		fields, opts, eventType, traceEventSampleDecoder{})
	if err != nil {
		monitor.decoders.RemoveDecoder(name)
		return 0, err
	}

	return eventid, nil
}

// RegisterExternalEvent is used to register an event that can be injected into
// the EventMonitor event stream from an external source. An event ID is
// returned that is unique to the EventMonitor and is to be used to unregister
// the event. The event ID will also be passed to the EventMonitor's dispatch
// function.
func (monitor *EventMonitor) RegisterExternalEvent(
	name string,
	decoderFn TraceEventDecoderFn,
) (uint64, error) {
	event := &registeredEvent{
		name:      name,
		eventType: EventTypeExternal,
	}
	event.decoder = externalEventSampleDecoder{decoderFn: decoderFn}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event.id = monitor.nextEventID
	monitor.nextEventID++

	if monitor.isRunning {
		monitor.events.insert(event.id, event)
	} else {
		monitor.events.insertInPlace(event.id, event)
	}

	return event.id, nil
}

// CounterEventGroupMember defines a counter event group member at registration
// time. Each member must have an event type of software, hardware, or
// hardware cache, as well as a configuration value that specifies what counter
// information to return.
type CounterEventGroupMember struct {
	EventType EventType
	Config    uint64
}

// RegisterCounterEventGroup registers a performance counter event group.
func (monitor *EventMonitor) RegisterCounterEventGroup(
	name string,
	counters []CounterEventGroupMember,
	decoderFn CounterEventDecoderFn,
	options ...RegisterEventOption,
) (int32, uint64, error) {
	if len(counters) < 1 {
		return 0, 0, errors.New("At least one counter must be specified")
	}
	for i, c := range counters {
		switch c.EventType {
		case EventTypeHardware, EventTypeHardwareCache, EventTypeSoftware:
			continue
		default:
			s, ok := EventTypeNames[c.EventType]
			if !ok {
				s = fmt.Sprintf("%d", c.EventType)
			}
			return 0, 0, fmt.Errorf("Counter %d event type %s is invalid",
				i, s)
		}
	}

	opts := processRegisterEventOptions(options...)
	if len(opts.filter) > 0 {
		return 0, 0, errors.New("Counter events do not support filters")
	}
	if opts.groupID != 0 {
		return 0, 0, errors.New("Counter events are their own groups")
	}

	if opts.eventAttr == nil {
		opts.eventAttr = &EventAttr{}
	} else {
		attr := *opts.eventAttr
		opts.eventAttr = &attr
	}
	opts.eventAttr.SampleType |= PERF_SAMPLE_READ
	opts.eventAttr.ReadFormat = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
		PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING
	opts.eventAttr.Disabled = opts.disabled
	fixupEventAttr(opts.eventAttr)

	// For our purposes, leaders should always be pinned. Note that
	// fixupEventAttr() sets Pinned to false for all other events in the
	// group.
	leaderAttr := *opts.eventAttr
	leaderAttr.Type = perfTypeFromEventType(counters[0].EventType)
	leaderAttr.Config = counters[0].Config
	leaderAttr.Pinned = true
	group, err := monitor.newEventGroup(&leaderAttr)
	if err != nil {
		return 0, 0, err
	}
	group.name = name

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	monitor.registerNewEventGroup(group)
	opts.groupID = group.groupID

	decoder := counterEventSampleDecoder{decoderFn: decoderFn}

	newfds := make([]int, len(group.leaders))
	for i, leader := range group.leaders {
		newfds[i] = leader.fd
	}
	eventID, err := monitor.newRegisteredEvent(name, newfds, nil,
		counters[0].EventType, decoder, &leaderAttr, group, true)
	if err != nil {
		monitor.unregisterEventGroup(group)
		return 0, 0, err
	}

	for i := 1; i < len(counters); i++ {
		_, err = monitor.newRegisteredPerfEvent(
			name, counters[i].Config, nil, opts,
			counters[i].EventType, decoder)
		if err != nil {
			monitor.unregisterEventGroup(group)
			return 0, 0, err
		}
	}

	return group.groupID, eventID, nil
}

// RegisterTracepoint is used to register a tracepoint with an EventMonitor.
// The tracepoint is selected by name and it must exist in the running Linux
// kernel. An event ID is returned that is unique to the EventMonitor and is
// to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterTracepoint(
	name string,
	fn TraceEventDecoderFn,
	options ...RegisterEventOption,
) (uint64, error) {
	opts := processRegisterEventOptions(options...)

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	return monitor.newRegisteredTraceEvent(name, fn, opts, EventTypeTracepoint)
}

// RegisterKprobe is used to register a kprobe with an EventMonitor. The kprobe
// will first be registered with the kernel, and then registered with the
// EventMonitor. An event ID is returned that is unqiue to the EventMonitor and
// is to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterKprobe(
	address string,
	onReturn bool,
	output string,
	fn TraceEventDecoderFn,
	options ...RegisterEventOption,
) (uint64, error) {
	opts := processRegisterEventOptions(options...)

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	name := monitor.newProbeName()
	err := monitor.addKprobe(name, address, onReturn, output)
	if err != nil {
		return 0, err
	}

	eventid, err := monitor.newRegisteredTraceEvent(name, fn, opts, EventTypeKprobe)
	if err != nil {
		monitor.removeKprobe(name)
		return 0, err
	}

	return eventid, nil
}

// RegisterUprobe is used to register a uprobe with an EventMonitor. The uprobe
// will first be registered with the kernel, and then registered with the
// EventMonitor. An event ID is returned that is unique to the EventMonitor and
// is to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterUprobe(
	bin string,
	address string,
	onReturn bool,
	output string,
	fn TraceEventDecoderFn,
	options ...RegisterEventOption,
) (uint64, error) {
	opts := processRegisterEventOptions(options...)

	// If the address looks like a symbol that needs to be resolved, it
	// must be resolved here and now. The kernel does not do symbol
	// resolution for uprobes.
	if address[0] == '_' || unicode.IsLetter(rune(address[0])) {
		var err error
		address, err = monitor.resolveSymbol(bin, address)
		if err != nil {
			return 0, err
		}
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	name := monitor.newProbeName()
	err := monitor.addUprobe(name, bin, address, onReturn, output)
	if err != nil {
		return 0, err
	}

	eventid, err := monitor.newRegisteredTraceEvent(name, fn, opts, EventTypeUprobe)
	if err != nil {
		monitor.removeUprobe(name)
		return 0, err
	}

	return eventid, nil
}

func baseAddress(file *elf.File, vaddr uint64) uint64 {
	if file.FileHeader.Type != elf.ET_EXEC {
		return 0
	}

	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}

		if vaddr < prog.Vaddr || vaddr >= prog.Vaddr+prog.Memsz {
			continue
		}

		return prog.Vaddr
	}

	return 0
}

func symbolOffset(file *elf.File, name string, symbols []elf.Symbol) uint64 {
	for _, sym := range symbols {
		if sym.Name == name {
			return sym.Value - baseAddress(file, sym.Value)
		}
	}

	return 0
}

func (monitor *EventMonitor) resolveSymbol(bin, symbol string) (string, error) {
	file, err := elf.Open(bin)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// We don't know how to deal with anything other than ET_DYN or
	// ET_EXEC types.
	if file.FileHeader.Type != elf.ET_DYN && file.FileHeader.Type != elf.ET_EXEC {
		return "", fmt.Errorf("Executable is of unsupported ELF type %d",
			file.FileHeader.Type)
	}

	// Check symbols followed by dynamic symbols. Ignore errors from either
	// one, because they'll just be about the sections not existing, which
	// is fine. In the end, we'll generate our own error to return to the
	// caller if the symbol isn't found.

	var offset uint64
	symbols, _ := file.Symbols()
	offset = symbolOffset(file, symbol, symbols)
	if offset == 0 {
		symbols, _ = file.DynamicSymbols()
		offset = symbolOffset(file, symbol, symbols)
		if offset == 0 {
			return "", fmt.Errorf("Symbol %q not found in %q",
				symbol, bin)
		}
	}

	return fmt.Sprintf("%#x", offset), nil
}

func (monitor *EventMonitor) removeRegisteredEvent(event *registeredEvent) {
	// This should be called with monitor.lock held

	// event.fds may legitimately be nil for non-perf_event-based events
	if event.fds != nil {
		ids := make([]uint64, 0, len(event.fds))
		for _, fd := range event.fds {
			delete(monitor.eventfds, fd)
			id, ok := monitor.eventids[fd]
			if ok {
				ids = append(ids, id)
				delete(monitor.eventids, fd)
			}
			if !event.leader {
				unix.Close(fd)
			}
		}

		if monitor.isRunning {
			monitor.eventAttrMap.remove(ids)
			monitor.eventIDMap.remove(ids)
		} else {
			monitor.eventAttrMap.removeInPlace(ids)
			monitor.eventIDMap.removeInPlace(ids)
		}
	}

	// Not all events belong to a group. In particular, external events do
	// not.
	if event.group != nil {
		delete(event.group.events, event.id)
	}

	switch event.eventType {
	case EventTypeTracepoint:
		monitor.decoders.RemoveDecoder(event.name)
	case EventTypeKprobe:
		monitor.removeKprobe(event.name)
		monitor.decoders.RemoveDecoder(event.name)
	case EventTypeUprobe:
		monitor.removeUprobe(event.name)
		monitor.decoders.RemoveDecoder(event.name)
	}
}

// UnregisterEvent is used to remove a previously registered event from an
// EventMonitor. The event can be of any type and is specified by the event
// ID that was returned when the event was initially registered with the
// EventMonitor.
func (monitor *EventMonitor) UnregisterEvent(eventid uint64) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if !ok {
		return errors.New("event is not registered")
	}
	if monitor.isRunning {
		monitor.events.remove(eventid)
	} else {
		monitor.events.removeInPlace(eventid)
	}
	monitor.removeRegisteredEvent(event)

	return nil
}

// RegisteredEventType returns the type of an event
func (monitor *EventMonitor) RegisteredEventType(
	eventID uint64,
) (EventType, bool) {
	event, ok := monitor.events.lookup(eventID)
	if !ok {
		return EventTypeInvalid, false
	}
	return event.eventType, true
}

// RegisteredEventFields returns the fields that are defined for the specified
// event identifier.
func (monitor *EventMonitor) RegisteredEventFields(
	eventID uint64,
) map[string]int32 {
	if event, ok := monitor.events.lookup(eventID); ok {
		return event.fields
	}
	return nil
}

// Close gracefully cleans up an EventMonitor instance. If the EventMonitor
// is still running when Close is called, it will first be stopped. After
// Close completes, the EventMonitor instance cannot be reused.
func (monitor *EventMonitor) Close() error {
	// if the monitor is running, stop it and wait for it to stop
	monitor.Stop(true)

	// This lock isn't strictly necessary -- by the time .Close() is
	// called, it would be a programming error for multiple go routines
	// to be trying to close the monitor or update events. It doesn't
	// hurt to lock, so do it anyway just to be on the safe side.
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	for _, group := range monitor.groups {
		group.cleanup()
	}
	monitor.groups = nil

	for _, event := range monitor.events.getMap() {
		monitor.removeRegisteredEvent(event)
	}
	monitor.events = nil

	if len(monitor.eventfds) != 0 {
		panic("internal error: stray event fds left after monitor Close")
	}
	monitor.eventfds = nil

	if len(monitor.eventids) != 0 {
		panic("internal error: stray event ids left after monitor Close")
	}
	monitor.eventids = nil

	if len(monitor.eventAttrMap.getMap()) != 0 {
		panic("internal error: stray event attrs left after monitor Close")
	}
	monitor.eventAttrMap = nil

	if len(monitor.eventIDMap.getMap()) != 0 {
		panic("internal error: stray event IDs left after monitor Close")
	}
	monitor.eventIDMap = nil

	groups := monitor.groupLeaders.getMap()
	for _, pgl := range groups {
		pgl.cleanup()
	}
	monitor.groupLeaders = nil

	if monitor.cgroups != nil {
		for _, fd := range monitor.cgroups {
			unix.Close(fd)
		}
		monitor.cgroups = nil
	}

	if monitor.epollFD != -1 {
		unix.Close(monitor.epollFD)
		monitor.epollFD = -1
	}

	return nil
}

// Disable is used to disable a registered event. The event to disable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Disable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if ok {
		for _, fd := range event.fds {
			disable(fd)
		}
	}
}

// DisableAll disables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) DisableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	// Group FDs are always disabled
	for fd := range monitor.eventfds {
		disable(fd)
	}
}

// DisableGroup disables all events for an event group.
func (monitor *EventMonitor) DisableGroup(groupID int32) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	group, ok := monitor.groups[groupID]
	if !ok {
		return fmt.Errorf("Group ID %d does not exist", groupID)
	}

	group.disable()

	return nil
}

// Enable is used to enable a registered event. The event to enable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Enable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if ok {
		for _, fd := range event.fds {
			enable(fd)
		}
	}
}

// EnableAll enables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) EnableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	// Group FDs are always disabled
	for fd := range monitor.eventfds {
		enable(fd)
	}
}

// EnableGroup enables all events for an event group.
func (monitor *EventMonitor) EnableGroup(groupID int32) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	group, ok := monitor.groups[groupID]
	if !ok {
		return fmt.Errorf("Group ID %d does not exist", groupID)
	}

	group.enable()

	return nil
}

// SetFilter is used to set or remove a filter from a registered event.
func (monitor *EventMonitor) SetFilter(eventid uint64, filter string) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if ok {
		for _, fd := range event.fds {
			err := setFilter(fd, filter)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (monitor *EventMonitor) stopWithSignal() {
	monitor.lock.Lock()
	monitor.isRunning = false
	monitor.cond.Broadcast()
	monitor.lock.Unlock()
}

// EventMonitorSample is an encapsulation of a sample from the EventMonitor
// interface. It contains the raw sample, decoded data, translated sample,
// and any error that may have occurred while processing the sample.
type EventMonitorSample struct {
	// EventID is the event ID that generated the sample. This is the ID
	// returned by one of the event registration functions.
	EventID uint64

	// RawSample is the raw sample from the perf_event interface.
	RawSample Sample

	// DecodedData is the sample data decoded from RawSample.Record.RawData
	// if RawSample is of type *SampleRecord; otherwise, it will be nil.
	DecodedData TraceEventSampleData

	// DecodedSample is the value returned from calling the registered
	// decoder for RawSample and DecodedData together.
	DecodedSample interface{}

	// Err will be non-nil if any occurred during processing of RawSample.
	Err error
}

// externalSampleList implements sort.Interface and is used for sorting a list
// of externalSample instances by time in descending order.
type externalSampleList []EventMonitorSample

func (l externalSampleList) Len() int {
	return len(l)
}

func (l externalSampleList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func (l externalSampleList) Less(i, j int) bool {
	return l[i].RawSample.Time > l[j].RawSample.Time
}

// EnqueueExternalSample enqueues an external sample to a registered external
// eventID. Events may not be enqueued for eventIDs that are not registered or
// not registered as external. Events with timestamps that fall outside the
// eventstream will be dropped.
func (monitor *EventMonitor) EnqueueExternalSample(
	eventID uint64,
	sampleID SampleID,
	decodedData TraceEventSampleData,
) error {
	event, ok := monitor.events.lookup(eventID)
	if !ok {
		return fmt.Errorf("Invalid eventID %d", eventID)
	}
	if event.eventType != EventTypeExternal {
		return fmt.Errorf("EventID %d is not an external type", eventID)
	}
	if sampleID.Time == 0 {
		return fmt.Errorf("Invalid sample time (%d)", sampleID.Time)
	}

	esm := EventMonitorSample{
		EventID:     eventID,
		DecodedData: decodedData,
	}
	esm.RawSample.Type = PERF_RECORD_SAMPLE
	esm.RawSample.Record = &SampleRecord{
		Pid:  sampleID.PID,
		Tid:  sampleID.TID,
		Time: sampleID.Time,
		CPU:  sampleID.CPU,
	}
	esm.RawSample.PID = sampleID.PID
	esm.RawSample.TID = sampleID.TID
	esm.RawSample.Time = sampleID.Time
	esm.RawSample.CPU = sampleID.CPU

	var updateMonitorGoRoutine = false

	monitor.lock.Lock()
	monitor.externalSamples = append(monitor.externalSamples, esm)
	if monitor.nextExternalSampleTime == 0 ||
		sampleID.Time < monitor.nextExternalSampleTime {
		monitor.nextExternalSampleTime = sampleID.Time
		updateMonitorGoRoutine = true
	}
	monitor.lock.Unlock()

	if updateMonitorGoRoutine {
		var buffer = make([]byte, 8)
		binary.LittleEndian.PutUint64(buffer, sampleID.Time)
		syscall.Write(monitor.pipe[1], buffer)
	}

	return nil
}

func (monitor *EventMonitor) processExternalSamples(timeLimit uint64) bool {
	if monitor.externalSamples != nil {
		monitor.lock.Lock()
		externalSamples := monitor.externalSamples
		monitor.externalSamples = nil
		monitor.nextExternalSampleTime = 0
		monitor.lock.Unlock()

		monitor.pendingExternalSamples = append(
			monitor.pendingExternalSamples, externalSamples...)
		sort.Sort(monitor.pendingExternalSamples)
	}

	if len(monitor.pendingExternalSamples) == 0 {
		return false
	}

	batch := make([]EventMonitorSample, 0, len(monitor.pendingExternalSamples))
	eventMap := monitor.events.getMap()
	for len(monitor.pendingExternalSamples) > 0 {
		l := len(monitor.pendingExternalSamples)
		esm := monitor.pendingExternalSamples[l-1]
		if esm.RawSample.Time > timeLimit {
			break
		}
		monitor.pendingExternalSamples =
			monitor.pendingExternalSamples[:l-1]
		event, ok := eventMap[esm.EventID]
		if !ok {
			continue
		}
		if esm.Err == nil {
			event.decoder.decodeSample(&esm, monitor)
			if esm.Err != nil || esm.DecodedSample != nil {
				batch = append(batch, esm)
			}
		} else {
			batch = append(batch, esm)
		}
	}

	l := len(monitor.pendingExternalSamples)
	if l > 0 {
		monitor.lock.Lock()
		nextTimeout := monitor.pendingExternalSamples[l-1].RawSample.Time
		monitor.nextExternalSampleTime = nextTimeout
		monitor.lock.Unlock()

		if nextTimeout > 0 {
			var buffer = make([]byte, 8)
			binary.LittleEndian.PutUint64(buffer, nextTimeout)
			syscall.Write(monitor.pipe[1], buffer)
		}
	}

	if len(batch) > 0 {
		monitor.dispatchFn(batch)
		return true
	}
	return false
}

type sampleMerger struct {
	samples [][]EventMonitorSample
	indices []int
}

func (m *sampleMerger) next() (EventMonitorSample, bool) {
	nSources := len(m.indices)
	if nSources == 0 {
		return EventMonitorSample{}, true
	}

	// Samples from each ringbuffer will be in timestamp order; therefore,
	// we can simpy look at the first element in each source to find the
	// next one to return.

	if nSources == 1 {
		sample := m.samples[0][m.indices[0]]
		m.indices[0]++
		if m.indices[0] == len(m.samples[0]) {
			m.samples = nil
			m.indices = nil
		}
		return sample, false
	}

	index := 0
	value := m.samples[0][m.indices[0]].RawSample.Time
	for i := 1; i < nSources; i++ {
		if v := m.samples[i][m.indices[i]].RawSample.Time; v < value {
			index = i
			value = v
		}
	}
	sample := m.samples[index][m.indices[index]]

	m.indices[index]++
	if m.indices[index] == len(m.samples[index]) {
		nSources--
		m.indices[index] = m.indices[nSources]
		m.indices = m.indices[:nSources]
		m.samples[index] = m.samples[nSources]
		m.samples = m.samples[:nSources]
	}

	return sample, false
}

func newSampleMerger(samples [][]EventMonitorSample) sampleMerger {
	return sampleMerger{
		samples: samples,
		indices: make([]int, len(samples)),
	}
}

func (monitor *EventMonitor) dispatchSamples(samples [][]EventMonitorSample) {
	dispatchFn := monitor.dispatchFn
	eventIDMap := monitor.eventIDMap.getMap()
	eventMap := monitor.events.getMap()

	nsamples := 0
	for _, s := range samples {
		nsamples += len(s)
	}
	batch := make([]EventMonitorSample, 0, nsamples)

	m := newSampleMerger(samples)
	for {
		esm, done := m.next()
		if done {
			break
		}

		if len(monitor.externalSamples) > 0 ||
			len(monitor.pendingExternalSamples) > 0 {
			if len(batch) > 0 {
				dispatchFn(batch)
				batch = make([]EventMonitorSample, 0,
					nsamples-len(batch))
			}
			monitor.processExternalSamples(esm.RawSample.Time)
		}

		if esm.EventID == 0 {
			streamID := esm.RawSample.SampleID.StreamID
			if eventID, ok := eventIDMap[streamID]; ok {
				esm.EventID = eventID
			} else {
				continue
			}
		}

		event, ok := eventMap[esm.EventID]
		if !ok {
			// If not ok, the eventID has been removed while we're
			// still processing samples. Drop it
			continue
		}

		switch record := esm.RawSample.Record.(type) {
		case *SampleRecord:
			// Adjust the sample time so that it
			// matches the normalized timestamp.
			record.Time = esm.RawSample.Time
		}
		if esm.Err == nil {
			event.decoder.decodeSample(&esm, monitor)
			if esm.Err != nil || esm.DecodedSample != nil {
				batch = append(batch, esm)
			}
		} else {
			batch = append(batch, esm)
		}
		if esm.RawSample.Time > monitor.lastSampleTimeDispatched {
			monitor.lastSampleTimeDispatched = esm.RawSample.Time
		}
	}

	if len(batch) > 0 {
		dispatchFn(batch)
	}
	monitor.processExternalSamples(monitor.lastSampleTimeDispatched)
}

func (monitor *EventMonitor) dispatchSampleLoop() {
	defer monitor.wg.Done()

	for monitor.isRunning {
		var samples [][]EventMonitorSample

		monitor.lock.Lock()
		if !monitor.isRunning {
			monitor.lock.Unlock()
			break
		}
		qs := monitor.dispatchQueueHead
		if qs != nil {
			samples = qs.samples
			monitor.dispatchQueueHead = qs.next
			if monitor.dispatchQueueHead == nil {
				monitor.dispatchQueueTail = nil
			}

			qs.next = monitor.dispatchFreeList
			qs.samples = nil
			monitor.dispatchFreeList = qs
		} else if !monitor.dispatchExternalSamples {
			monitor.cond.Wait()
		}
		monitor.dispatchExternalSamples = false
		monitor.lock.Unlock()

		if len(samples) > 0 {
			monitor.dispatchSamples(samples)
		} else {
			now := sys.CurrentMonotonicRaw()
			monitor.processExternalSamples(uint64(now))
		}
	}
}

func (monitor *EventMonitor) enqueueSamples(samples [][]EventMonitorSample) {
	if len(samples) == 0 {
		return
	}

	monitor.lock.Lock()

	qs := monitor.dispatchFreeList
	if qs == nil {
		qs = &queuedSamples{}
	} else {
		monitor.dispatchFreeList = qs.next
		qs.next = nil
	}
	qs.samples = samples

	if monitor.dispatchQueueTail == nil {
		monitor.dispatchQueueHead = qs
	} else {
		monitor.dispatchQueueTail.next = qs
	}
	monitor.dispatchQueueTail = qs

	monitor.cond.Broadcast()
	monitor.lock.Unlock()
}

func (monitor *EventMonitor) readRingBuffers() {
	// Clear the monitor's hasPendingSamples flag immediately. All samples
	// pending at this time will be included for processing. New pending
	// samples may be added and so this flag will be updated later.
	monitor.hasPendingSamples = false

	var lastTimestamp uint64
	fds := make(map[int]bool)
	groupLeaders := monitor.groupLeaders.getMap()
	samples := make([][]EventMonitorSample, 0, len(groupLeaders))
	for _, pgl := range groupLeaders {
		var groupSamples, newPendingSamples []EventMonitorSample

		// If the pgl's state is not active, skip it. Either we need to
		// to clean it up later or it has already been cleaned up.
		// Either way, we're not interested in its ringbuffer (and in
		// the latter case, we'd segfault)
		switch atomic.LoadInt32(&pgl.state) {
		case perfGroupLeaderStateActive:
			break
		case perfGroupLeaderStateClosing:
			fds[pgl.fd] = true
			pgl.cleanup()
			continue
		default:
			continue
		}

		pgl.rb.read(func(data []byte) {
			attrMap := monitor.eventAttrMap.getMap()
			r := bytes.NewReader(data)
			for r.Len() > 0 {
				ems := EventMonitorSample{}
				ems.Err = ems.RawSample.read(r, nil, attrMap)
				ems.RawSample.Time =
					uint64(int64(ems.RawSample.Time) -
						timeOffsets[pgl.cpu] +
						timeBase)
				groupSamples = append(groupSamples, ems)
			}
		})

		if len(groupSamples) == 0 {
			if len(pgl.pendingSamples) > 0 {
				samples = append(samples, pgl.pendingSamples)
			}
			pgl.pendingSamples = nil
			continue
		}

		if lastTimestamp == 0 {
			lastTimestamp = groupSamples[len(groupSamples)-1].RawSample.Time
		} else {
			l := len(groupSamples)
			for i := l - 1; i >= 0; i-- {
				if groupSamples[i].RawSample.Time <= lastTimestamp {
					break
				}
				l--
			}
			if l != len(groupSamples) {
				monitor.hasPendingSamples = true
				newPendingSamples = groupSamples[l:]
				groupSamples = groupSamples[:l]
				if len(groupSamples) == 0 {
					pgl.pendingSamples = newPendingSamples
					continue
				}
			}
		}

		groupSamples = append(pgl.pendingSamples, groupSamples...)
		pgl.pendingSamples = newPendingSamples
		samples = append(samples, groupSamples)
	}

	if len(fds) > 0 {
		go func() {
			monitor.groupLeaders.remove(fds)
		}()
	}

	monitor.enqueueSamples(samples)
}

func (monitor *EventMonitor) flushPendingSamples() {
	var samples [][]EventMonitorSample
	for _, pgl := range monitor.groupLeaders.getMap() {
		if atomic.LoadInt32(&pgl.state) == perfGroupLeaderStateClosing {
			pgl.cleanup()
			continue
		}
		if len(pgl.pendingSamples) > 0 {
			samples = append(samples, pgl.pendingSamples)
			pgl.pendingSamples = nil
		}
	}

	monitor.hasPendingSamples = false
	monitor.enqueueSamples(samples)
}

// Go does not provide fcntl(). We need to provide it for ourselves
func fcntl(fd, cmd int, flag uintptr) (uintptr, error) {
	r1, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), flag)
	return r1, errno
}

// Run puts an EventMonitor into the running state. While an EventMonitor is
// running, samples will be pulled from event sources, decoded, and dispatched
// to a function that is specified here.
func (monitor *EventMonitor) Run(fn SampleDispatchFn) error {
	monitor.lock.Lock()
	if monitor.isRunning {
		monitor.lock.Unlock()
		return errors.New("monitor is already running")
	}
	monitor.isRunning = true

	err := unix.Pipe(monitor.pipe[:])
	monitor.lock.Unlock()
	if err != nil {
		monitor.stopWithSignal()
		return err
	}
	f, _ := fcntl(monitor.pipe[0], syscall.F_GETFL, 0)
	fcntl(monitor.pipe[0], syscall.F_SETFL, f|syscall.O_NONBLOCK)

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     -1,
	}
	err = unix.EpollCtl(monitor.epollFD, unix.EPOLL_CTL_ADD,
		monitor.pipe[0], &event)

	monitor.dispatchFn = fn

	monitor.wg.Add(1)
	go monitor.dispatchSampleLoop()

	var nextTimeout int64
	events := make([]unix.EpollEvent, len(monitor.groupLeaders.getMap()))

runloop:
	for {
		var n int

		// If there are pending samples, check for waiting events and
		// return immediately. If there aren't any, flush everything
		// pending and go back to waiting for events normally. If there
		// are events, the pending events will get handled during
		// normal processing
		if monitor.hasPendingSamples {
			n, err = unix.EpollWait(monitor.epollFD, events, 0)
			if err != nil && err != unix.EINTR {
				break
			}
			if n == 0 {
				monitor.flushPendingSamples()
				continue
			}
		} else {
			var timeout int
			if nextTimeout == 0 {
				timeout = -1
			} else {
				now := sys.CurrentMonotonicRaw()
				if now > nextTimeout {
					nextTimeout = 0
					timeout = 0
				} else {
					timeout = int((nextTimeout - now) / 1e6)
				}
			}
			n, err = unix.EpollWait(monitor.epollFD, events, timeout)
			if err != nil && err != unix.EINTR {
				break
			}
		}

		if n == 0 {
			if monitor.nextExternalSampleTime != 0 {
				monitor.lock.Lock()
				monitor.dispatchExternalSamples = true
				monitor.cond.Broadcast()
				monitor.lock.Unlock()
			}
		} else if n > 0 {
			ringBuffersReady := false
			for i := 0; i < n; i++ {
				e := events[i]
				if e.Fd == -1 {
					if e.Events & ^uint32(unix.EPOLLIN) != 0 {
						// EPOLLERR, EPOLLHUP, etc.
						break runloop
					}
					if e.Events&unix.EPOLLIN != unix.EPOLLIN {
						continue
					}
					fd := monitor.pipe[0]
					for {
						var buffer = make([]byte, 8)

						_, err = syscall.Read(fd, buffer)
						if err != nil {
							if err == syscall.EINTR {
								continue
							}
							break
						}
						v := int64(binary.LittleEndian.Uint64(buffer))
						if nextTimeout == 0 || v < nextTimeout {
							nextTimeout = v
						}
					}
				} else if (e.Events & unix.EPOLLIN) != 0 {
					ringBuffersReady = true
				}
			}
			if ringBuffersReady {
				monitor.readRingBuffers()
			} else if monitor.hasPendingSamples {
				monitor.flushPendingSamples()
			}
		}
	}

	monitor.lock.Lock()
	if monitor.pipe[1] != -1 {
		unix.Close(monitor.pipe[1])
		monitor.pipe[1] = -1
	}
	if monitor.pipe[0] != -1 {
		unix.Close(monitor.pipe[0])
		monitor.pipe[0] = -1
	}
	monitor.lock.Unlock()

	monitor.stopWithSignal()

	return err
}

// Stop stops a running EventMonitor. If the EventMonitor is not running, this
// function does nothing. Once an EventMonitor has been stopped, it may be
// restarted again. Whether Stop waits for the EventMonitor to fully stop is
// optional, but if the caller does not wait there is no other mechanism by
// which the caller may learn whether the EventMonitor is stopped.
func (monitor *EventMonitor) Stop(wait bool) {
	monitor.lock.Lock()

	if !monitor.isRunning {
		monitor.lock.Unlock()
		return
	}

	if monitor.pipe[1] != -1 {
		fd := monitor.pipe[1]
		monitor.pipe[1] = -1
		unix.Close(fd)
	}

	if !wait {
		monitor.lock.Unlock()
	} else {
		for monitor.isRunning {
			// Wait for condition to signal that Run() is done
			monitor.cond.Wait()
		}
		monitor.lock.Unlock()

		// Wait for other goroutines to exit
		monitor.wg.Wait()
	}
}

func collectReferenceSamples(ncpu int) (int64, int64, []int64, error) {
	referenceEventAttr := &EventAttr{
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_CPU_CLOCK,
		SampleFreq:   1,
		SampleType:   PERF_SAMPLE_TIME,
		Disabled:     true,
		Freq:         true,
		WakeupEvents: 1,
	}

	rbs := make([]*ringBuffer, ncpu)
	pollfds := make([]unix.PollFd, ncpu)
	for cpu := 0; cpu < ncpu; cpu++ {
		fd, err := open(referenceEventAttr, -1, cpu, -1, 0)
		if err != nil {
			err = fmt.Errorf("Couldn't open reference event: %s", err)
			return 0, 0, nil, err
		}
		defer unix.Close(fd)
		pollfds[cpu] = unix.PollFd{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		}

		rbs[cpu], err = newRingBuffer(fd, 1)
		if err != nil {
			err = fmt.Errorf("Couldn't allocate ringbuffer: %s", err)
			return 0, 0, nil, err
		}
		defer rbs[cpu].unmap()
	}

	// Enable all of the events we just registered
	for _, p := range pollfds {
		enable(int(p.Fd))
	}

	var firstTime int64
	startTime := sys.CurrentMonotonicRaw()

	// Read all samples from each group, but keep only the first for each
	// Don't wait forever. Return a timeout error if samples don't arrive
	// within 2 seconds.
	const timeout = 2 * time.Second
	glog.V(2).Infof("Calculating CPU time offsets (max wait %d nsec)", timeout)

	nsamples := 0
	samples := make([]int64, ncpu)
	timeoutAt := sys.CurrentMonotonicRaw() + int64(timeout)
	for nsamples < ncpu {
		now := sys.CurrentMonotonicRaw()
		if now >= timeoutAt {
			return 0, 0, nil, errors.New("Timeout while reading samples")
		}
		n, err := unix.Poll(pollfds, int((timeoutAt-now)/int64(time.Millisecond)))
		if err != nil && err != unix.EINTR {
			return 0, 0, nil, err
		}
		if n == 0 {
			continue
		}
		if firstTime == 0 {
			firstTime = sys.CurrentMonotonicRaw()
		}

		for cpu, p := range pollfds {
			if p.Revents&unix.POLLIN != unix.POLLIN {
				continue
			}

			rbs[cpu].read(func(data []byte) {
				r := bytes.NewReader(data)
				s := Sample{}
				err := s.read(r, referenceEventAttr, nil)
				if err == nil {
					samples[cpu] = int64(s.Time)
					nsamples++
				}
			})

			if samples[cpu] != 0 {
				pollfds[cpu].Events &= ^unix.POLLIN
			}
		}
	}

	return startTime, firstTime, samples, nil
}

func calculateTimeOffsets(procfs proc.FileSystem) error {
	ncpu := procfs.HostFileSystem().NumCPU()
	timeOffsets = make([]int64, ncpu)
	if haveClockID {
		return nil
	}

	// Obtain references samples, one for each CPU.
	startTime, firstTime, samples, err := collectReferenceSamples(ncpu)
	if err != nil {
		return err
	}

	timeBase = startTime
	for cpu := 0; cpu < ncpu; cpu++ {
		timeOffsets[cpu] = samples[cpu] - (firstTime - startTime)
		glog.V(2).Infof("EventMonitor CPU %d time offset is %d\n",
			cpu, timeOffsets[cpu])
	}

	return nil
}

var groupEventAttr = EventAttr{
	Type:     PERF_TYPE_SOFTWARE,
	Config:   PERF_COUNT_SW_DUMMY, // Added in Linux 3.12
	Disabled: true,
}

func (monitor *EventMonitor) initializeGroupLeaders(
	pid int,
	flags uintptr,
	attr *EventAttr,
) ([]*perfGroupLeader, error) {
	if attr == nil {
		attr = &groupEventAttr
	}

	var err error
	ncpu := monitor.procFS.NumCPU()
	pgls := make([]*perfGroupLeader, ncpu)
	for cpu := 0; cpu < ncpu; cpu++ {
		var fd int
		fd, err = open(attr, pid, cpu, -1, flags)
		if err != nil {
			break
		}

		pgls[cpu] = &perfGroupLeader{
			pid:   pid,
			cpu:   cpu,
			fd:    fd,
			flags: flags,
			state: perfGroupLeaderStateActive,
		}

		pgls[cpu].rb, err = newRingBuffer(fd, monitor.ringBufferNumPages)
		if err != nil {
			break
		}

		event := unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(fd),
		}
		err = unix.EpollCtl(monitor.epollFD, unix.EPOLL_CTL_ADD,
			fd, &event)
		if err != nil {
			break
		}
	}

	if err != nil {
		for _, pgl := range pgls {
			if pgl == nil {
				break
			}
			pgl.cleanup()
		}
		return nil, err
	}

	return pgls, nil
}

func (monitor *EventMonitor) newEventGroup(
	attr *EventAttr,
) (*eventMonitorGroup, error) {
	ncpu := monitor.procFS.NumCPU()
	nleaders := (len(monitor.cgroups) + len(monitor.pids)) * ncpu
	leaders := make([]*perfGroupLeader, 0, nleaders)

	if monitor.cgroups != nil {
		flags := monitor.perfEventOpenFlags | PERF_FLAG_PID_CGROUP
		for _, fd := range monitor.cgroups {
			pgls, err := monitor.initializeGroupLeaders(fd, flags,
				attr)
			if err != nil {
				for _, pgl := range leaders {
					pgl.cleanup()
				}
				return nil, err
			}
			leaders = append(leaders, pgls...)
		}
	}

	if monitor.pids != nil {
		flags := monitor.perfEventOpenFlags
		for _, pid := range monitor.pids {
			pgls, err := monitor.initializeGroupLeaders(pid, flags,
				attr)
			if err != nil {
				for _, pgl := range leaders {
					pgl.cleanup()
				}
				return nil, err
			}
			leaders = append(leaders, pgls...)
		}
	}

	return &eventMonitorGroup{
		leaders: leaders,
		events:  make(map[uint64]*registeredEvent),
		monitor: monitor,
	}, nil
}

func (monitor *EventMonitor) registerNewEventGroup(group *eventMonitorGroup) {
	// This should be called with monitor.lock LOCKED!

	group.groupID = monitor.nextGroupID
	monitor.nextGroupID++
	monitor.groups[group.groupID] = group

	if monitor.isRunning {
		monitor.groupLeaders.update(group.leaders)
	} else {
		monitor.groupLeaders.updateInPlace(group.leaders)
	}
}

// RegisterEventGroup creates a new event group that can be used for grouping
// events.
func (monitor *EventMonitor) RegisterEventGroup(name string) (int32, error) {
	group, err := monitor.newEventGroup(nil)
	if err != nil {
		return -1, err
	}
	group.name = name

	monitor.lock.Lock()
	monitor.registerNewEventGroup(group)
	monitor.lock.Unlock()

	if len(group.name) == 0 {
		group.name = fmt.Sprintf("EventGroup %d", group.groupID)
	}

	return group.groupID, nil
}

func (monitor *EventMonitor) unregisterEventGroup(group *eventMonitorGroup) {
	// This should be called with monitor.lock LOCKED!!

	delete(monitor.groups, group.groupID)

	group.cleanup()

	if !monitor.isRunning {
		fds := make(map[int]bool, len(group.leaders))
		for _, pgl := range group.leaders {
			fds[pgl.fd] = true
			pgl.cleanup()
		}
		monitor.groupLeaders.removeInPlace(fds)
	} else {
		for _, pgl := range group.leaders {
			atomic.StoreInt32(&pgl.state, perfGroupLeaderStateClosing)
		}
	}
}

// UnregisterEventGroup removes a registered event group. If there are any
// events registered with the event group, they will be unregistered as well.
func (monitor *EventMonitor) UnregisterEventGroup(groupID int32) error {
	monitor.lock.Lock()
	group, ok := monitor.groups[groupID]
	if !ok {
		monitor.lock.Unlock()
		return fmt.Errorf("Group ID %d does not exist", groupID)
	}

	monitor.unregisterEventGroup(group)

	monitor.lock.Unlock()
	return nil
}

func doProbeCleanup(
	tracingDir, eventsFile string,
	activePids, deadPids map[int]bool,
) {
	eventsFilename := filepath.Join(tracingDir, eventsFile)
	data, err := ioutil.ReadFile(eventsFilename)
	if err != nil {
		return
	}

	var file *os.File

	// Read one line at a time and check for capsule8/sensor_ probes. The
	// pid that created the probe is encoded within. If the pid is dead,
	// remove the probe.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		name := line[2:strings.Index(line, " ")]
		if !strings.HasPrefix(name, "capsule8/sensor_") {
			continue
		}

		// Capsule8 sensor names are of the form sensor_<pid>_<count>
		var pid int
		fmt.Sscanf(name, "capsule8/sensor_%d_", &pid)
		if activePids[pid] {
			continue
		} else if !deadPids[pid] {
			if syscall.Kill(pid, 0) != syscall.ESRCH {
				activePids[pid] = true
				continue
			}
			deadPids[pid] = true
		}

		cmd := fmt.Sprintf("-:%s\n", name)
		if file == nil {
			file, err = os.OpenFile(eventsFilename, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				glog.Errorf("Couldn't open %s WO+A: %s", eventsFilename, err)
				return
			}
			defer file.Close()
		}
		file.Write([]byte(cmd))
		glog.V(1).Infof("Removed stale probe from %s: %s", eventsFile, name)
	}
}

func cleanupStaleProbes(tracingDir string) {
	activePids := make(map[int]bool)
	deadPids := make(map[int]bool)

	activePids[os.Getpid()] = true

	doProbeCleanup(tracingDir, "kprobe_events", activePids, deadPids)
	doProbeCleanup(tracingDir, "uprobe_events", activePids, deadPids)
}

// NewEventMonitor creates a new EventMonitor instance in the stopped state.
// Once an EventMonitor instance is returned from this function, its Close
// method must be called to clean it up gracefully, even if no events are
// registered or it is never put into the running state.
func NewEventMonitor(options ...EventMonitorOption) (*EventMonitor, error) {
	opts := eventMonitorOptions{}
	for _, option := range options {
		option(&opts)
	}

	// Use the specified procfs as-is or find the host procfs to use if
	// not explicitly specified.
	if opts.procfs == nil {
		procfs, err := procfs.NewFileSystem("")
		if err != nil {
			return nil, err
		}
		opts.procfs = procfs.HostFileSystem()
		if opts.procfs == nil {
			return nil, errors.New("Unable to determine host procfs")
		}
	}

	eventMonitorOnce.Do(func() {
		attr := EventAttr{
			SamplePeriod:    1,
			Disabled:        true,
			UseClockID:      true,
			ClockID:         unix.CLOCK_MONOTONIC_RAW,
			Watermark:       true,
			WakeupWatermark: 1,
		}
		fd, err := open(&attr, 0, -1, -1, 0)
		if err == nil {
			unix.Close(fd)
			haveClockID = true
			groupEventAttr.UseClockID = true
			groupEventAttr.ClockID = unix.CLOCK_MONOTONIC_RAW
		}
		calculateTimeOffsets(opts.procfs)
	})
	if haveClockID && !notedClockID {
		glog.V(1).Infof("EventMonitor is using ClockID CLOCK_MONOTONIC_RAW")
		notedClockID = true
	}

	var eventAttr EventAttr

	if opts.defaultEventAttr == nil {
		eventAttr = EventAttr{
			SampleType: PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
		}
	} else {
		eventAttr = *opts.defaultEventAttr
	}
	fixupEventAttr(&eventAttr)

	// Only allow certain flags to be passed
	opts.flags &= PERF_FLAG_FD_CLOEXEC

	// If no tracing dir was specified, scan mounts for one
	if len(opts.tracingDir) == 0 {
		opts.tracingDir = opts.procfs.TracingDir()
	}
	cleanupStaleProbes(opts.tracingDir)

	// If no perf_event cgroup mountpoint was specified, scan mounts for one
	if len(opts.perfEventDir) == 0 && len(opts.cgroups) > 0 {
		opts.perfEventDir = opts.procfs.PerfEventDir()

		// If we didn't find one, we can't monitor specific cgroups
		if len(opts.perfEventDir) == 0 {
			return nil, errors.New("Can't monitor specific cgroups without perf_event cgroupfs")
		}
	}

	// If no pids or cgroups were specified, default to monitoring the
	// whole system (pid -1)
	if len(opts.pids) == 0 && len(opts.cgroups) == 0 {
		opts.pids = append(opts.pids, -1)
	}

	epollFD, err := unix.EpollCreate1(0)
	if err != nil {
		return nil, err
	}

	// Beyond this point, always call monitor.Close() if there's an error
	// so that everything gets properly cleaned up. In particular, epoll_fd
	// and cgroup fds if there are any.

	monitor := &EventMonitor{
		groupLeaders:       newSafePerfGroupLeaderMap(),
		epollFD:            epollFD,
		eventAttrMap:       newSafeEventAttrMap(),
		eventIDMap:         newSafeUInt64Map(),
		decoders:           newTraceEventDecoderMap(opts.tracingDir),
		events:             newSafeRegisteredEventMap(),
		nextEventID:        1,
		groups:             make(map[int32]*eventMonitorGroup),
		eventfds:           make(map[int]int),
		eventids:           make(map[int]uint64),
		defaultAttr:        eventAttr,
		tracingDir:         opts.tracingDir,
		procFS:             opts.procfs,
		ringBufferNumPages: opts.ringBufferNumPages,
		perfEventOpenFlags: opts.flags,
	}
	monitor.cond = sync.Cond{L: &monitor.lock}

	if len(opts.cgroups) > 0 {
		cgroups := make(map[string]bool, len(opts.cgroups))
		monitor.cgroups = make([]int, 0, len(opts.cgroups))
		for _, cgroup := range opts.cgroups {
			if cgroups[cgroup] {
				glog.V(1).Infof("Ignoring duplicate cgroup %s",
					cgroup)
				continue
			}
			cgroups[cgroup] = true

			var fd int
			path := filepath.Join(opts.perfEventDir, cgroup)
			fd, err = unix.Open(path, unix.O_RDONLY, 0)
			if err != nil {
				monitor.Close()
				return nil, err
			}
			monitor.cgroups = append(monitor.cgroups, fd)
		}
	}

	if len(opts.pids) > 0 {
		pids := make(map[int]bool, len(opts.pids))
		monitor.pids = make([]int, 0, len(opts.pids))
		for _, pid := range opts.pids {
			if pids[pid] {
				glog.V(1).Infof("Ignoring duplicate pid %d",
					pid)
				continue
			}
			pids[pid] = true

			monitor.pids = append(monitor.pids, pid)
		}
	}

	_, err = monitor.RegisterEventGroup("default")
	if err != nil {
		monitor.Close()
		return nil, err
	}

	return monitor, nil
}
