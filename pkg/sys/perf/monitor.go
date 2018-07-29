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
	"unicode"

	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/proc"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"
	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

type eventMonitorOptions struct {
	eventSourceController EventSourceController
	procfs                proc.FileSystem
	flags                 uintptr
	defaultEventAttr      *EventAttr
	perfEventDir          string
	tracingDir            string
	ringBufferNumPages    int
	cgroups               []string
	pids                  []int
}

// EventMonitorOption is used to implement optional arguments for
// NewEventMonitor. It must be exported, but it is not typically
// used directly.
type EventMonitorOption func(*eventMonitorOptions)

func newEventMonitorOptions() eventMonitorOptions {
	return eventMonitorOptions{}
}

func (opts *eventMonitorOptions) processOptions(
	options ...EventMonitorOption,
) {
	for _, option := range options {
		option(opts)
	}
}

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

// WithEventSourceController is used to set the event source controller to be
// used. If left unspecified, the default system event source controller will
// be used. Any controller specified here will be owned immediately by
// NewEventMonitor, which primarily means that its Close method will be called
// if any error occurs while creating the new EventMonitor. If an EventMonitor
// is created successfully, the event source controller's Close method will not
// be called until the monitor's Close method is called.
func WithEventSourceController(controller EventSourceController) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.eventSourceController = controller
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
	name      string
}

// RegisterEventOption is used to implement optional arguments for event
// registration methods. It must be exported, but it is not typically used
// directly.
type RegisterEventOption func(*registerEventOptions)

func newRegisterEventOptions() registerEventOptions {
	return registerEventOptions{
		disabled: true,
	}
}

func (opts *registerEventOptions) processOptions(
	options ...RegisterEventOption,
) {
	for _, option := range options {
		option(opts)
	}
}

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

// WithTracingEventName is used to specify the name of a kprobe or uprobe to
// use for registration instead of an automatically generated one.
func WithTracingEventName(name string) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.name = name
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

func unboxNil(i interface{}) interface{} {
	switch v := reflect.ValueOf(i); v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return nil
		}
	}
	return i
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
	if d.decoderFn != nil {
		var s interface{}
		s, esm.Err = d.decoderFn(
			esm.RawSample.Record.(*SampleRecord),
			esm.DecodedData)
		esm.DecodedSample = unboxNil(s)
	}
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
	if d.decoderFn != nil {
		if sample, ok := esm.RawSample.Record.(*SampleRecord); ok {
			attrMap := monitor.eventAttrMap.getMap()
			counters := make([]CounterEventValue, 0, len(sample.V.Values))
			for _, v := range sample.V.Values {
				var attr EventAttr
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
			esm.DecodedSample = unboxNil(s)
		}
	}
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
	esm.DecodedSample = unboxNil(s)
}

type registeredEvent struct {
	id        uint64
	name      string
	sources   []EventSource // one source per cpu
	fields    map[string]int32
	decoder   eventSampleDecoder
	eventType EventType
	group     *eventMonitorGroup
	leader    bool
}

const (
	perfGroupLeaderStateActive int32 = iota
	perfGroupLeaderStateClosing
	perfGroupLeaderStateClosed
)

type perfGroupLeader struct {
	source EventSourceLeader

	// Mutable only by the monitor goroutine while running. No
	// synchronization is required.
	pendingSamples []EventMonitorSample

	// This is the event's state. Normally it will be active. When a group
	// is being removed, it will transition to closing, which means that
	// the ringbuffer servicing goroutine should ignore it. That goroutine
	// will call .cleanup() for the event and transition it to the closed
	// state, which means that it can be safely removed by any goroutine at
	// any point in the future.
	state int32
}

func (pgl *perfGroupLeader) cleanup() {
	pgl.source.Close()
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
	for _, event := range group.events {
		monitor.removeRegisteredEvent(event)
	}
}

func (group *eventMonitorGroup) disable() {
	for _, event := range group.events {
		for _, source := range event.sources {
			source.Disable()
		}
	}
}

func (group *eventMonitorGroup) enable() {
	for _, event := range group.events {
		for _, source := range event.sources {
			source.Enable()
		}
	}
}

func (group *eventMonitorGroup) perfEventOpen(
	name string,
	eventAttr EventAttr,
	filter string,
	flags uintptr,
) (sources []EventSource, err error) {
	glog.V(2).Infof("Opening perf event: %s (%d) in group %d %q {%s}",
		name, eventAttr.Config, group.groupID, group.name, filter)

	newsources := make([]EventSource, 0, len(group.leaders))
	defer func() {
		if err != nil {
			for j := len(newsources) - 1; j >= 0; j-- {
				newsources[j].Close()
			}
		}
	}()

	for _, pgl := range group.leaders {
		var source EventSource
		if source, err = pgl.source.NewEventSource(eventAttr, flags); err != nil {
			return
		}
		newsources = append(newsources, source)

		if len(filter) > 0 {
			if err = source.SetFilter(filter); err != nil {
				return
			}
		}
	}

	sources = newsources
	return
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
	eventSourceController EventSourceController

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

	// Mutable by the thread on which Stop is called.
	stopRequested bool

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

	// Mutable by various goroutines, but not required by the monitor goroutine
	nextEventID            uint64
	nextProbeID            uint64
	nextGroupID            int32
	groups                 map[int32]*eventMonitorGroup
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

// DoesTracepointExist returns true if the named tracepoint exists on the
// system; otherwise, it returns false.
func (monitor *EventMonitor) DoesTracepointExist(name string) bool {
	dirname := filepath.Join(monitor.tracingDir, "events", name)
	if i, err := os.Stat(dirname); err == nil {
		return i.IsDir()
	}
	return false
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

func (monitor *EventMonitor) addKprobe(
	name string,
	address string,
	onReturn bool,
	output string,
) error {
	output = strings.Join(strings.Fields(output), " ")

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
	output = strings.Join(strings.Fields(output), " ")

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
	probeName := monitor.NextProbeName()
	monitor.nextProbeID++
	return probeName
}

// NextProbeName is used primarily for unit testing. It returns the next probe
// name that will be used by either RegisterKprobe or RegisterUprobe.
func (monitor *EventMonitor) NextProbeName() string {
	return fmt.Sprintf("capsule8/sensor_%d_%d", unix.Getpid(),
		monitor.nextProbeID+1)
}

func (monitor *EventMonitor) newRegisteredEvent(
	name string,
	newsources []EventSource,
	fields map[string]int32,
	eventType EventType,
	decoder eventSampleDecoder,
	attr EventAttr,
	group *eventMonitorGroup,
	leader bool,
) uint64 {
	eventid := monitor.nextEventID
	monitor.nextEventID++

	if len(newsources) > 0 {
		eventAttrMap := newEventAttrMap()
		eventIDMap := newUInt64Map()
		for _, source := range newsources {
			id := source.SourceID()
			eventAttrMap[id] = attr
			eventIDMap[id] = eventid
		}

		if monitor.isRunning {
			monitor.eventAttrMap.update(eventAttrMap)
			monitor.eventIDMap.update(eventIDMap)
		} else {
			monitor.eventAttrMap.updateInPlace(eventAttrMap)
			monitor.eventIDMap.updateInPlace(eventIDMap)
		}
	}

	event := &registeredEvent{
		id:        eventid,
		name:      name,
		sources:   newsources,
		fields:    fields,
		decoder:   decoder,
		eventType: eventType,
		group:     group,
		leader:    leader,
	}
	// External events don't have groups, so nil check here
	if group != nil {
		group.events[eventid] = event
	}

	if monitor.isRunning {
		monitor.events.insert(eventid, event)
	} else {
		monitor.events.insertInPlace(eventid, event)
	}

	return eventid
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
	attr.Type = perfTypeFromEventType(eventType)
	attr.Config = config
	attr.Disabled = opts.disabled

	switch eventType {
	case EventTypeTracepoint, EventTypeKprobe, EventTypeUprobe:
		flags = PERF_FLAG_FD_OUTPUT | PERF_FLAG_FD_NO_GROUP
	}

	group, ok := monitor.groups[opts.groupID]
	if !ok {
		return 0, fmt.Errorf("Group ID %d does not exist", opts.groupID)
	}

	newsources, err := group.perfEventOpen(name, attr, opts.filter, flags)
	if err != nil {
		return 0, err
	}

	eventid := monitor.newRegisteredEvent(name, newsources, fields,
		eventType, decoder, attr, group, false)
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
) uint64 {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	decoder := externalEventSampleDecoder{decoderFn: decoderFn}
	eventid := monitor.newRegisteredEvent(
		name,
		nil,
		nil,
		EventTypeExternal,
		decoder,
		EventAttr{},
		nil,
		false)

	return eventid
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

	opts := newRegisterEventOptions()
	opts.processOptions(options...)
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
	group, err := monitor.newEventGroup(leaderAttr)
	if err != nil {
		return 0, 0, err
	}
	group.name = name

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	monitor.registerNewEventGroup(group)
	opts.groupID = group.groupID

	decoder := counterEventSampleDecoder{decoderFn: decoderFn}

	newsources := make([]EventSource, len(group.leaders))
	for i, leader := range group.leaders {
		newsources[i] = leader.source
	}
	eventID := monitor.newRegisteredEvent(name, newsources, nil,
		counters[0].EventType, decoder, leaderAttr, group, true)
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
	opts := newRegisterEventOptions()
	opts.processOptions(options...)

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
	opts := newRegisterEventOptions()
	opts.processOptions(options...)

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	var name string
	if opts.name == "" {
		name = monitor.newProbeName()
	} else {
		name = fmt.Sprintf("capsule8/sensor_%d_%s",
			os.Getpid(), opts.name)
	}
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
	opts := newRegisterEventOptions()
	opts.processOptions(options...)

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

	var name string
	if opts.name == "" {
		name = monitor.newProbeName()
	} else {
		name = fmt.Sprintf("capsule8/sensor_%d_%s",
			os.Getpid(), opts.name)
	}
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

	if monitor.isRunning {
		monitor.events.remove(event.id)
	} else {
		monitor.events.removeInPlace(event.id)
	}

	// event.sources may legitimately be nil for non-perf_event-based events
	if event.sources != nil {
		ids := make([]uint64, 0, len(event.sources))
		for _, source := range event.sources {
			ids = append(ids, source.SourceID())
			if !event.leader {
				source.Close()
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

	if event, ok := monitor.events.lookup(eventid); ok {
		monitor.removeRegisteredEvent(event)
		return nil
	}
	return errors.New("event is not registered")
}

// RegisteredEventType returns the type of an event
func (monitor *EventMonitor) RegisteredEventType(
	eventID uint64,
) (EventType, bool) {
	if event, ok := monitor.events.lookup(eventID); ok {
		return event.eventType, true
	}
	return EventTypeInvalid, false
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

	// Make a copy of monitor.events.getMap() values so that we're not
	// enumerating and mutating the map at the same time.
	eventsMap := monitor.events.getMap()
	eventsList := make([]*registeredEvent, 0, len(eventsMap))
	for _, event := range eventsMap {
		eventsList = append(eventsList, event)
	}
	for _, event := range eventsList {
		monitor.removeRegisteredEvent(event)
	}
	monitor.events = nil

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

	if monitor.eventSourceController != nil {
		monitor.eventSourceController.Close()
		monitor.eventSourceController = nil
	}

	return nil
}

// Disable is used to disable a registered event. The event to disable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Disable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if event, ok := monitor.events.lookup(eventid); ok {
		for _, source := range event.sources {
			source.Disable()
		}
	}
}

// DisableAll disables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) DisableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	for _, event := range monitor.events.getMap() {
		for _, source := range event.sources {
			source.Disable()
		}
	}
}

// DisableGroup disables all events for an event group.
func (monitor *EventMonitor) DisableGroup(groupID int32) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if group, ok := monitor.groups[groupID]; ok {
		group.disable()
		return nil
	}
	return fmt.Errorf("Group ID %d does not exist", groupID)
}

// Enable is used to enable a registered event. The event to enable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Enable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if event, ok := monitor.events.lookup(eventid); ok {
		for _, source := range event.sources {
			source.Enable()
		}
	}
}

// EnableAll enables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) EnableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	for _, event := range monitor.events.getMap() {
		for _, source := range event.sources {
			source.Enable()
		}
	}
}

// EnableGroup enables all events for an event group.
func (monitor *EventMonitor) EnableGroup(groupID int32) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if group, ok := monitor.groups[groupID]; ok {
		group.enable()
		return nil
	}
	return fmt.Errorf("Group ID %d does not exist", groupID)
}

// SetFilter is used to set or remove a filter from a registered event.
func (monitor *EventMonitor) SetFilter(eventid uint64, filter string) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if event, ok := monitor.events.lookup(eventid); ok {
		for _, source := range event.sources {
			if err := source.SetFilter(filter); err != nil {
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

func (monitor *EventMonitor) setNextExternalSampleTime(t uint64) {
	if monitor.nextExternalSampleTime == 0 || t < monitor.nextExternalSampleTime {
		monitor.nextExternalSampleTime = t
		monitor.eventSourceController.SetTimeoutAt(int64(t))
	}
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

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if monitor.events == nil {
		// This is an enqueue after Stop runs
		return nil
	}
	event, ok := monitor.events.lookup(eventID)
	if !ok {
		return fmt.Errorf("Invalid eventID %d", eventID)
	}
	if event.eventType != EventTypeExternal {
		return fmt.Errorf("EventID %d is not an external type", eventID)
	}

	monitor.externalSamples = append(monitor.externalSamples, esm)
	monitor.setNextExternalSampleTime(sampleID.Time)

	return nil
}

func (monitor *EventMonitor) processExternalSamples(timeLimit uint64) bool {
	if monitor.externalSamples != nil {
		monitor.lock.Lock()
		externalSamples := monitor.externalSamples
		monitor.externalSamples = nil
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

	monitor.lock.Lock()
	if l := len(monitor.pendingExternalSamples); l > 0 {
		nextTimeout := monitor.pendingExternalSamples[l-1].RawSample.Time
		monitor.setNextExternalSampleTime(nextTimeout)
	} else if len(monitor.externalSamples) == 0 {
		monitor.nextExternalSampleTime = 0
	}
	monitor.lock.Unlock()

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

		if esm.Err == nil {
			event.decoder.decodeSample(&esm, monitor)
		}
		if esm.Err != nil || esm.DecodedSample != nil {
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

	for {
		monitor.lock.Lock()
		if !monitor.isRunning {
			monitor.lock.Unlock()
			break
		}
		samples := monitor.dequeueSamples()
		if samples == nil && !monitor.dispatchExternalSamples {
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

func (monitor *EventMonitor) dequeueSamples() [][]EventMonitorSample {
	var samples [][]EventMonitorSample

	if qs := monitor.dispatchQueueHead; qs != nil {
		samples = qs.samples
		monitor.dispatchQueueHead = qs.next
		if monitor.dispatchQueueHead == nil {
			monitor.dispatchQueueTail = nil
		}
		qs.next = monitor.dispatchFreeList
		qs.samples = nil
		monitor.dispatchFreeList = qs
	}
	return samples
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

func (monitor *EventMonitor) readEventSources() {
	// Clear the monitor's hasPendingSamples flag immediately. All samples
	// pending at this time will be included for processing. New pending
	// samples may be added and so this flag will be updated later.
	monitor.hasPendingSamples = false

	var lastTimestamp uint64
	ids := make(map[uint64]struct{})
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
			ids[pgl.source.SourceID()] = struct{}{}
			pgl.cleanup()
			continue
		default:
			continue
		}

		attrMap := monitor.eventAttrMap.getMap()
		pgl.source.Read(attrMap, func(sample Sample, err error) {
			ems := EventMonitorSample{
				Err:       err,
				RawSample: sample,
			}
			groupSamples = append(groupSamples, ems)
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
				if len(groupSamples) == 0 && len(pgl.pendingSamples) == 0 {
					pgl.pendingSamples = newPendingSamples
					continue
				}
			}
		}

		groupSamples = append(pgl.pendingSamples, groupSamples...)
		pgl.pendingSamples = newPendingSamples
		samples = append(samples, groupSamples)
	}

	if len(ids) > 0 {
		go func() {
			monitor.groupLeaders.remove(ids)
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

// Run puts an EventMonitor into the running state. While an EventMonitor is
// running, samples will be pulled from event sources, decoded, and dispatched
// to a function that is specified here.
func (monitor *EventMonitor) Run(fn SampleDispatchFn) error {
	monitor.lock.Lock()
	if monitor.isRunning {
		monitor.lock.Unlock()
		return errors.New("monitor is already running")
	}
	monitor.dispatchFn = fn
	monitor.isRunning = true
	monitor.stopRequested = false
	monitor.lock.Unlock()

	monitor.wg.Add(1)
	go monitor.dispatchSampleLoop()

	defer monitor.stopWithSignal()

	for {
		var timeoutAt int64
		if monitor.hasPendingSamples {
			// If there are pending samples, check for waiting
			// events, but return immediately if there aren't any.
			timeoutAt = 0
		} else {
			// This lock here really isn't necessary, but Go's race
			// detector won't pass without it. We're about to go
			// into a wait anyway, so it has no real performance
			// impact.
			monitor.lock.Lock()
			if t := monitor.nextExternalSampleTime; t == 0 {
				timeoutAt = -1
			} else {
				timeoutAt = int64(t)
			}
			monitor.lock.Unlock()
		}

		err := monitor.eventSourceController.Wait(timeoutAt)
		if err == nil {
			monitor.readEventSources()
		} else if err == unix.ETIMEDOUT {
			if monitor.hasPendingSamples {
				monitor.flushPendingSamples()
			} else {
				// Same issue as above. Go's race detector
				// insists on this lock.
				monitor.lock.Lock()
				if monitor.nextExternalSampleTime != 0 {
					monitor.dispatchExternalSamples = true
					monitor.cond.Broadcast()
				}
				monitor.lock.Unlock()
			}
		} else {
			monitor.stopWithSignal()
			return err
		}
		if monitor.stopRequested {
			break
		}
	}

	return nil
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

	// Request a stop by setting the flag and waking up the goroutine that
	// is handling events from source leaders.
	monitor.stopRequested = true
	monitor.eventSourceController.SetTimeoutAt(0)

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

var groupEventAttr = EventAttr{
	Type:     PERF_TYPE_SOFTWARE,
	Config:   PERF_COUNT_SW_DUMMY, // Added in Linux 3.12
	Disabled: true,
}

func (monitor *EventMonitor) initializeGroupLeaders(
	pid int,
	flags uintptr,
	attr EventAttr,
) ([]*perfGroupLeader, error) {
	var err error
	ncpu := monitor.procFS.NumCPU()
	pgls := make([]*perfGroupLeader, ncpu)
	for cpu := 0; cpu < ncpu; cpu++ {
		var source EventSourceLeader

		source, err =
			monitor.eventSourceController.NewEventSourceLeader(
				attr, pid, cpu, flags)
		if err != nil {
			break
		}

		pgls[cpu] = &perfGroupLeader{
			source: source,
			state:  perfGroupLeaderStateActive,
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
	attr EventAttr,
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
	group, err := monitor.newEventGroup(groupEventAttr)
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
		ids := make(map[uint64]struct{}, len(group.leaders))
		for _, pgl := range group.leaders {
			ids[pgl.source.SourceID()] = struct{}{}
			pgl.cleanup()
		}
		monitor.groupLeaders.removeInPlace(ids)
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
	defer monitor.lock.Unlock()

	var err error
	if group, ok := monitor.groups[groupID]; ok {
		monitor.unregisterEventGroup(group)
	} else {
		err = fmt.Errorf("Group ID %d does not exist", groupID)
	}
	return err
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
func NewEventMonitor(options ...EventMonitorOption) (monitor *EventMonitor, err error) {
	opts := eventMonitorOptions{}
	opts.processOptions(options...)

	defer func() {
		if err != nil {
			if monitor != nil {
				monitor.Close()
				monitor = nil
			} else if opts.eventSourceController != nil {
				opts.eventSourceController.Close()
			}
		}
	}()

	// Use the specified procfs as-is or find the host procfs to use if
	// not explicitly specified.
	if opts.procfs == nil {
		var fs *procfs.FileSystem
		if fs, err = procfs.NewFileSystem(""); err != nil {
			return
		}
		if opts.procfs = fs.HostFileSystem(); opts.procfs == nil {
			err = errors.New("Unable to determine host procfs")
			return
		}
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
			err = errors.New("Can't monitor specific cgroups without perf_event cgroupfs")
			return
		}
	}

	// If no pids or cgroups were specified, default to monitoring the
	// whole system (pid -1)
	if len(opts.pids) == 0 && len(opts.cgroups) == 0 {
		opts.pids = append(opts.pids, -1)
	}

	// Use the system default event source controller if a specific one to
	// use is not specified.
	if opts.eventSourceController == nil {
		// The shenanigans here are intentional to avoid Go insanity
		// in assigning (*defaultEventSourceController)(nil) to
		// opts.eventSourceController if newDefaultEventSourceController
		// also returns an error (triggering a panic in the deferred
		// cleanup above)
		var controller EventSourceController
		controller, err = newDefaultEventSourceController(opts)
		if err != nil {
			return
		}
		opts.eventSourceController = controller
	}
	monitor = &EventMonitor{
		groupLeaders:          newSafePerfGroupLeaderMap(),
		eventSourceController: opts.eventSourceController,
		eventAttrMap:          newSafeEventAttrMap(),
		eventIDMap:            newSafeUInt64Map(),
		decoders:              newTraceEventDecoderMap(opts.tracingDir),
		events:                newSafeRegisteredEventMap(),
		nextEventID:           1,
		groups:                make(map[int32]*eventMonitorGroup),
		defaultAttr:           eventAttr,
		tracingDir:            opts.tracingDir,
		procFS:                opts.procfs,
		ringBufferNumPages:    opts.ringBufferNumPages,
		perfEventOpenFlags:    opts.flags,
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
				return
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
	return
}
