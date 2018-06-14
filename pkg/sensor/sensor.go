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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/capsule8/capsule8/pkg/sys/proc"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"

	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

type newSensorOptions struct {
	perfEventDir string
	tracingDir   string
	procFS       proc.FileSystem
}

// NewSensorOption is used to implement optional arguments for NewSensor.
// It must be exported, but it is not typically used directly.
type NewSensorOption func(*newSensorOptions)

// WithProcFileSystem is used to set the proc.FileSystem to use. The system
// default will be used if one is not specified.
func WithProcFileSystem(procFS proc.FileSystem) NewSensorOption {
	return func(o *newSensorOptions) {
		o.procFS = procFS
	}
}

// WithPerfEventDir is used to set an optional directory to use for monitoring
// groups. This should only be necessary if the perf_event cgroup is not
// mounted in the usual location.
func WithPerfEventDir(perfEventDir string) NewSensorOption {
	return func(o *newSensorOptions) {
		o.perfEventDir = perfEventDir
	}
}

// WithTracingDir is used to set an alternate mountpoint to use for managing
// tracepoints, kprobes, and uprobes.
func WithTracingDir(tracingDir string) NewSensorOption {
	return func(o *newSensorOptions) {
		o.tracingDir = tracingDir
	}
}

// Number of random bytes to generate for Sensor Id
const sensorIDLengthBytes = 32

// Sensor represents the state of a sensor instance.
type Sensor struct {
	// Unique Id for this sensor. Sensor Ids are ephemeral.
	ID string

	// Sensor-unique event sequence number. Each event sent from this
	// sensor to any subscription has a unique sequence number for the
	// indicated sensor Id.
	sequenceNumber uint64

	// Record the value of CLOCK_MONOTONIC_RAW when the sensor starts.
	// All event monotimes are relative to this value.
	bootMonotimeNanos int64

	// Metrics counters for this sensor
	Metrics MetricsCounters

	// If temporary fs mounts are made at startup, they're stored here.
	perfEventDir        string
	tracingDir          string
	perfEventDirMounted bool
	tracingDirMounted   bool

	// A sensor-global event monitor that is used for events to aid in
	// caching process information
	Monitor *perf.EventMonitor

	// A reference to the host proc filesystem in use.
	ProcFS proc.FileSystem

	// A lookup table of available kernel symbols. The key is the symbol
	// name as would be used with RegisterKprobe. The value is the actual
	// symbol that should be used, which is normally the same, but can
	// sometimes differ due to compiler name mangling.
	kallsyms map[string]string

	// Per-sensor caches and monitors
	ProcessCache   *ProcessInfoCache
	ContainerCache *ContainerCache
	dockerMonitor  *dockerMonitor
	ociMonitor     *ociMonitor

	// Mapping of event ids to subscriptions
	eventMap *safeSubscriptionMap

	dispatchMutex     sync.Mutex
	dispatchCond      sync.Cond
	dispatchQueueHead *queuedSamples
	dispatchQueueTail *queuedSamples
	dispatchFreelist  *queuedSamples
	dispatchRunning   bool
	dispatchWaitGroup sync.WaitGroup

	// Used by syscall events to handle syscall enter events with
	// argument filters
	dummySyscallEventID    uint64
	dummySyscallEventCount int64
}

type queuedSamples struct {
	next    *queuedSamples
	samples []perf.EventMonitorSample
}

// NewSensor creates a new Sensor instance.
func NewSensor(options ...NewSensorOption) (*Sensor, error) {
	opts := newSensorOptions{}
	for _, option := range options {
		option(&opts)
	}

	if opts.procFS == nil {
		fs, err := procfs.NewFileSystem("")
		if err != nil {
			return nil, err
		}
		opts.procFS = fs.HostFileSystem()
		if opts.procFS == nil {
			return nil, errors.New("Cannot resolve host procfs")
		}
	}
	if len(opts.perfEventDir) == 0 {
		opts.perfEventDir = opts.procFS.PerfEventDir()
	}
	if len(opts.tracingDir) == 0 {
		opts.tracingDir = opts.procFS.TracingDir()
	}

	randomBytes := make([]byte, sensorIDLengthBytes)
	rand.Read(randomBytes)
	sensorID := hex.EncodeToString(randomBytes)

	s := &Sensor{
		ID:                sensorID,
		bootMonotimeNanos: sys.CurrentMonotonicRaw(),
		perfEventDir:      opts.perfEventDir,
		tracingDir:        opts.tracingDir,
		ProcFS:            opts.procFS,
		eventMap:          newSafeSubscriptionMap(),
	}
	s.dispatchCond = sync.Cond{L: &s.dispatchMutex}

	return s, nil
}

// Start starts a sensor instance running.
func (s *Sensor) Start() error {
	var buf unix.Utsname
	if err := unix.Uname(&buf); err == nil {
		machine := strings.TrimRight(string(buf.Machine[:]), "\000")
		nodename := strings.TrimRight(string(buf.Nodename[:]), "\000")
		sysname := strings.TrimRight(string(buf.Sysname[:]), "\000")
		release := strings.TrimRight(string(buf.Release[:]), "\000")
		version := strings.TrimRight(string(buf.Version[:]), "\000")
		glog.Infof("%s %s %s %s %s",
			machine, nodename, sysname, release, version)
	}

	// We require that our run dir (usually /var/run/capsule8) exists.
	// Ensure that now before proceeding any further.
	if err := os.MkdirAll(config.Global.RunDir, 0700); err != nil {
		glog.Warningf("Couldn't mkdir %s: %s",
			config.Global.RunDir, err)
		return err
	}

	// If there is no mounted tracefs, the Sensor really can't do anything.
	// Try mounting our own private mount of it.
	if !config.Sensor.DontMountTracing && len(s.tracingDir) == 0 {
		// If we couldn't find one, try mounting our own private one
		glog.V(2).Info("Can't find mounted tracefs, mounting one")
		if err := s.mountTraceFS(); err != nil {
			glog.V(1).Info(err)
			return err
		}
	}

	// If there is no mounted cgroupfs for the perf_event cgroup, we can't
	// efficiently separate processes in monitored containers from host
	// processes. We can run without it, but it's better performance when
	// available.
	if !config.Sensor.DontMountPerfEvent && len(s.perfEventDir) == 0 {
		glog.V(2).Info("Can't find mounted perf_event cgroupfs, mounting one")
		if err := s.mountPerfEventCgroupFS(); err != nil {
			glog.V(1).Info(err)
			// This is not a fatal error condition, proceed on
		}
	}

	// Create the sensor-global event monitor. This EventMonitor instance
	// will be used for all perf_event events
	err := s.createEventMonitor()
	if err != nil {
		s.Stop()
		return err
	}

	s.kallsyms, err = s.ProcFS.KernelTextSymbolNames()
	if err != nil {
		glog.Warning("Could not load kernel symbols: %v", err)
	}

	s.ContainerCache = NewContainerCache(s)
	s.ProcessCache = NewProcessInfoCache(s)
	s.ProcessCache.Start()

	if len(config.Sensor.DockerContainerDir) > 0 {
		s.dockerMonitor = newDockerMonitor(s,
			config.Sensor.DockerContainerDir)
		if s.dockerMonitor != nil {
			s.dockerMonitor.start()
		}
	}
	/* Temporarily disable the OCI monitor until a better means of
	   supporting it is found.
	if len(config.Sensor.OciContainerDir) > 0 {
		s.ociMonitor = newOciMonitor(s, config.Sensor.OciContainerDir)
		s.ociMonitor.start()
	}
	*/

	// Make sure that all events registered with the sensor's event monitor
	// are active
	s.Monitor.EnableGroup(0)

	// Start dispatch goroutine(s). We'll just spin one up for now, but we
	// can run multiples if we want. The sensor needs to keep samples in
	// order coming from the EventMonitor in order to maintain internal
	// consistency, but it makes no guarantees about the order in which
	// telemetry events are emitted to external clients.
	// NOTE: if more than one dispatch goroutine is spun up, then there
	// needs to be synchronization in containerFilter
	s.dispatchRunning = true
	s.dispatchWaitGroup.Add(1)
	go s.sampleDispatchLoop()

	return nil
}

// Stop stops a running sensor instance.
func (s *Sensor) Stop() {
	if s.dispatchRunning {
		s.dispatchMutex.Lock()
		if s.dispatchRunning {
			s.dispatchRunning = false
			s.dispatchCond.Broadcast()
			s.dispatchMutex.Unlock()
			s.dispatchWaitGroup.Wait()
		} else {
			s.dispatchMutex.Unlock()
		}
	}
	if s.Monitor != nil {
		glog.V(2).Info("Stopping sensor-global EventMonitor")
		s.Monitor.Close()
		s.Monitor = nil
		glog.V(2).Info("Sensor-global EventMonitor stopped successfully")
	}

	if s.tracingDirMounted {
		s.unmountTraceFS()
	}

	if s.perfEventDirMounted {
		s.unmountPerfEventCgroupFS()
	}
}

func (s *Sensor) mountTraceFS() error {
	dir := filepath.Join(config.Global.RunDir, "tracing")
	err := sys.MountTempFS("tracefs", dir, "tracefs", 0, "")
	if err == nil {
		s.tracingDir = dir
		s.tracingDirMounted = true
	}
	return err
}

func (s *Sensor) unmountTraceFS() {
	err := sys.UnmountTempFS(s.tracingDir, "tracefs")
	if err == nil {
		s.tracingDir = ""
		s.tracingDirMounted = false
	} else {
		glog.V(2).Infof("Could not unmount %s: %s", s.tracingDir, err)
	}
}

func (s *Sensor) mountPerfEventCgroupFS() error {
	dir := filepath.Join(config.Global.RunDir, "perf_event")
	err := sys.MountTempFS("cgroup", dir, "cgroup", 0, "perf_event")
	if err == nil {
		s.perfEventDir = dir
		s.perfEventDirMounted = true
	}
	return err
}

func (s *Sensor) unmountPerfEventCgroupFS() {
	err := sys.UnmountTempFS(s.perfEventDir, "cgroup")
	if err == nil {
		s.perfEventDir = ""
		s.perfEventDirMounted = false
	} else {
		glog.V(2).Infof("Could not unmount %s: %s", s.perfEventDir, err)
	}
}

// NewEvent creates a new API Event instance with common sensor-specific fields
// correctly populated.
func (s *Sensor) NewEvent() *api.TelemetryEvent {
	monotime := sys.CurrentMonotonicRaw() - s.bootMonotimeNanos

	// The first sequence number is intentionally 1 to disambiguate
	// from no sequence number being included in the protobuf message.
	sequenceNumber := atomic.AddUint64(&s.sequenceNumber, 1)

	var b []byte
	buf := bytes.NewBuffer(b)
	binary.Write(buf, binary.LittleEndian, s.ID)
	binary.Write(buf, binary.LittleEndian, sequenceNumber)
	binary.Write(buf, binary.LittleEndian, monotime)

	h := sha256.Sum256(buf.Bytes())
	eventID := hex.EncodeToString(h[:])

	atomic.AddUint64(&s.Metrics.Events, 1)

	return &api.TelemetryEvent{
		Id:                   eventID,
		SensorId:             s.ID,
		SensorMonotimeNanos:  monotime,
		SensorSequenceNumber: sequenceNumber,
	}
}

// NewEventFromContainer creates a new API Event instance using a specific
// container ID.
func (s *Sensor) NewEventFromContainer(containerID string) *api.TelemetryEvent {
	e := s.NewEvent()
	e.ContainerId = containerID
	return e
}

// NewEventFromSample creates a new API Event instance using perf_event sample
// information. If the sample comes from the calling process, no event will be
// created, and the return will be nil.
func (s *Sensor) NewEventFromSample(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) *api.TelemetryEvent {
	var (
		ok           bool
		leader, task *Task
	)

	// Avoid the lookup if we've been given the information.
	// This happens most commonly with process events.
	if task, ok = data["__task__"].(*Task); ok {
		leader = task.Leader()
	} else if pid, _ := data["common_pid"].(int32); pid != 0 {
		// When both the sensor and the process generating the sample
		// are in containers, the sample.Pid and sample.Tid fields will
		// be zero. Use "common_pid" from the trace event data instead.
		task, leader = s.ProcessCache.LookupTaskAndLeader(int(pid))
	}
	if leader != nil && leader.IsSensor() {
		return nil
	}

	e := s.NewEvent()
	e.SensorMonotimeNanos = int64(sample.Time) - s.bootMonotimeNanos
	e.Cpu = int32(sample.CPU)

	if task != nil {
		e.ProcessPid = int32(task.PID)
		e.ProcessId = task.ProcessID
		e.ProcessTgid = int32(task.TGID)

		if c := task.Creds; c != nil {
			e.Credentials = &api.Credentials{
				Uid:   c.UID,
				Gid:   c.GID,
				Euid:  c.EUID,
				Egid:  c.EGID,
				Suid:  c.SUID,
				Sgid:  c.SGID,
				Fsuid: c.FSUID,
				Fsgid: c.FSGID,
			}
		}

		// if task != nil, leader is also guaranteed != nil
		if i := s.ProcessCache.LookupTaskContainerInfo(leader); i != nil {
			e.ContainerId = i.ID
			e.ContainerName = i.Name
			e.ImageId = i.ImageID
			e.ImageName = i.ImageName
		}
	}

	return e
}

func (s *Sensor) buildMonitorGroups() ([]string, []int, error) {
	var (
		cgroupList []string
		pidList    []int
		system     bool
	)

	cgroups := make(map[string]bool)
	for _, cgroup := range config.Sensor.CgroupName {
		if len(cgroup) == 0 || cgroup == "/" {
			system = true
			continue
		}
		if cgroups[cgroup] {
			continue
		}
		cgroups[cgroup] = true
		cgroupList = append(cgroupList, cgroup)
	}

	// Try a system-wide perf event monitor if requested or as
	// a fallback if no cgroups were requested
	if system || len(s.perfEventDir) == 0 || len(cgroupList) == 0 {
		pidList = append(pidList, -1)
	}

	return cgroupList, pidList, nil
}

func (s *Sensor) createEventMonitor() error {
	eventMonitorOptions := []perf.EventMonitorOption{}
	eventMonitorOptions = append(eventMonitorOptions,
		perf.WithProcFileSystem(s.ProcFS))

	if len(s.tracingDir) > 0 {
		eventMonitorOptions = append(eventMonitorOptions,
			perf.WithTracingDir(s.tracingDir))
	}

	cgroups, pids, err := s.buildMonitorGroups()
	if err != nil {
		return err
	}

	if len(cgroups) == 0 && len(pids) == 0 {
		glog.Fatal("Can't create event monitor with no cgroups or pids")
	}

	if len(pids) > 0 {
		glog.V(1).Info("Creating new system-wide event monitor")
		eventMonitorOptions = append(eventMonitorOptions,
			perf.WithPids(pids))
	}

	var optionsWithoutCgroups []perf.EventMonitorOption
	copy(optionsWithoutCgroups, eventMonitorOptions)

	if len(cgroups) > 0 && len(s.perfEventDir) > 0 {
		glog.V(1).Infof("Creating new perf event monitor on cgroups %s",
			strings.Join(cgroups, ","))

		eventMonitorOptions = append(eventMonitorOptions,
			perf.WithPerfEventDir(s.perfEventDir),
			perf.WithCgroups(cgroups))
	}

	s.Monitor, err = perf.NewEventMonitor(eventMonitorOptions...)
	if err != nil {
		// If a cgroup-specific event monitor could not be created,
		// fall back to a system-wide event monitor.
		if len(cgroups) > 0 &&
			(len(pids) == 0 || (len(pids) == 1 && pids[0] == -1)) {

			glog.Warningf("Couldn't create perf event monitor on cgroups %s: %s",
				strings.Join(cgroups, ","), err)

			glog.V(1).Info("Creating new system-wide event monitor")
			s.Monitor, err = perf.NewEventMonitor(optionsWithoutCgroups...)
		}
		if err != nil {
			glog.V(1).Infof("Couldn't create event monitor: %s", err)
			return err
		}
	}

	go func() {
		err := s.Monitor.Run(s.dispatchSamples)
		if err != nil {
			glog.Fatal(err)
		}
		glog.V(2).Info("EventMonitor.Run() returned; exiting goroutine")
	}()

	return nil
}

// IsKernelSymbolAvailable checks to see if the specified kprobe symbol is
// available for use in the running kernel.
func (s *Sensor) IsKernelSymbolAvailable(symbol string) bool {
	// If the kallsyms mapping is nil, the table could not be
	// loaded for some reason; assume anything is available
	if s.kallsyms == nil {
		return true
	}

	_, ok := s.kallsyms[symbol]
	return ok
}

// Map for rewriting kprobe fetch args in kernel 4.17+
// N.B. %di must come first to avoid replacing a %di in an already replaced
// expression.
// N.B. %cx actually needs to be replaced with pt_regs->r10. Since the syscall
// handlers used to have "real" arguments, registers were setup according to the
// x64 _C_ ABI, however now the syscalls only get a pointer to the register state
// at the time the syscall entered, which means the registers are setup in the
// x64 _syscall_ ABI.
var fetchArgsReplacements = [][2]string{
	{"%di", "+0x70(%di)"}, // pt_regs+0x70
	{"%si", "+0x68(%di)"},
	{"%dx", "+0x60(%di)"},
	{"%cx", "+0x38(%di)"}, // This is actually replacing RCX with R10
	{"%r8", "+0x48(%di)"},
	{"%r9", "+0x40(%di)"},
	{"%ax", "+0x50(%di)"},
}

// RegisterKprobe registers a kprobe with the sensor's EventMonitor instance,
// but before doing so, ensures that the kernel symbol is available and potentially
// transforms it to account for new kernel changes.
func (s *Sensor) RegisterKprobe(
	address string,
	onReturn bool,
	output string,
	fn perf.TraceEventDecoderFn,
	options ...perf.RegisterEventOption,
) (uint64, error) {
	if s.kallsyms != nil {
		if actual, ok := s.kallsyms[address]; ok {
			if actual != address {
				glog.V(2).Infof("Using %q for kprobe symbol %q", actual, address)
				address = actual
			}
		} else {
			// Linux 4.17 changes how syscall handlers are done. It adds a `__x64_`
			// prefix and also changes how arguments are handled in the syscall handler.
			// Automatically try to prepend `__x64_` if we're registering a kprobe
			// on a syscall handler, and if it succeeds, rewrite the kprobe fetch args.
			if strings.HasPrefix(address, "sys_") {
				actual, ok := s.kallsyms["__x64_"+address]
				if ok {
					glog.V(2).Infof("Using %q for kprobe symbol %q", actual, address)
					address = actual

					// rewrite `output` (the kprobe fetch args) to account for
					// the only argument to the syscall handler being `pt_regs *regs`
					for _, rewritePair := range fetchArgsReplacements {
						srcReg := rewritePair[0]
						dstExpr := rewritePair[1]
						output = strings.Replace(output, srcReg, dstExpr, -1)
					}
					glog.V(2).Infof("Rewrote kprobe fetch args to %q", output)
				} else {
					return 0, fmt.Errorf("Kernel symbol not found: %s", address)
				}
			} else {
				return 0, fmt.Errorf("Kernel symbol not found: %s", address)
			}
		}
	}
	return s.Monitor.RegisterKprobe(address, onReturn, output, fn, options...)
}

// NewSubscription creates a new telemetry subscription
func (s *Sensor) NewSubscription() *Subscription {
	atomic.AddInt32(&s.Metrics.Subscriptions, 1)

	// Use an empty dispatch function until Subscription.Run is called with
	// the real dispatch function to use. This is to avoid an extra branch
	// during dispatch to check for a nil dispatchFn. Since under normal
	// operation this case is impossible, it's a waste to add the check
	// when it's so easy to handle otherwise during the subscription
	// window.
	return &Subscription{
		sensor:     s,
		dispatchFn: func(e *api.TelemetryEvent) {},
	}
}

func (s *Sensor) dispatchSamples(samples []perf.EventMonitorSample) {
	s.dispatchMutex.Lock()

	var qs *queuedSamples
	if s.dispatchFreelist == nil {
		qs = &queuedSamples{samples: samples}
	} else {
		qs = s.dispatchFreelist
		s.dispatchFreelist = qs.next
		qs.next = nil
		qs.samples = samples
	}

	if s.dispatchQueueTail == nil {
		s.dispatchQueueHead = qs
		s.dispatchCond.Signal()
	} else {
		s.dispatchQueueTail.next = qs
	}
	s.dispatchQueueTail = qs

	s.dispatchMutex.Unlock()
}

func (s *Sensor) popSamples() []perf.EventMonitorSample {
	qs := s.dispatchQueueHead
	samples := qs.samples

	s.dispatchQueueHead = qs.next
	if s.dispatchQueueHead == nil {
		s.dispatchQueueTail = nil
	}

	qs.next = s.dispatchFreelist
	qs.samples = nil
	s.dispatchFreelist = qs

	return samples
}

func (s *Sensor) dispatchQueuedSamples(samples []perf.EventMonitorSample) {
	eventMap := s.eventMap.getMap()
	for _, esm := range samples {
		if esm.Err != nil {
			glog.Warning(esm.Err)
			continue
		}

		event, ok := esm.DecodedSample.(*api.TelemetryEvent)
		if !ok || event == nil {
			continue
		}

		eventSinks, ok := eventMap[esm.EventID]
		if !ok {
			continue
		}

		for _, es := range eventSinks {
			if es.filter != nil {
				v, err := es.filter.Evaluate(
					es.filterTypes,
					expression.FieldValueMap(esm.DecodedData))
				if err != nil {
					glog.V(1).Infof("Expression evaluation error: %s", err)
					continue
				}
				if !expression.IsValueTrue(v) {
					continue
				}
			}
			s := es.subscription
			if s.containerFilter != nil &&
				!s.containerFilter.match(event) {
				continue
			}
			if cef, ok := event.Event.(*api.TelemetryEvent_Container); ok {
				if es.containerView != api.ContainerEventView_FULL {
					if len(eventSinks) > 1 {
						event = copyTelemetryEvent(event)
						cef = event.Event.(*api.TelemetryEvent_Container)
					}
					cef.Container.DockerConfigJson = ""
					cef.Container.OciConfigJson = ""
				}
			}
			s.dispatchFn(event)
		}
	}
}

func (s *Sensor) sampleDispatchLoop() {
	glog.V(2).Info("Sample dispatch loop started")

	s.dispatchMutex.Lock()
	for s.dispatchRunning {
		if s.dispatchQueueHead == nil {
			s.dispatchCond.Wait()
			continue
		}
		samples := s.popSamples()

		s.dispatchMutex.Unlock()
		s.dispatchQueuedSamples(samples)
		s.dispatchMutex.Lock()
	}
	s.dispatchMutex.Unlock()

	glog.V(2).Info("Sample dispatch loop stopped")
	s.dispatchWaitGroup.Done()
}

func copyTelemetryEvent(oldEvent *api.TelemetryEvent) *api.TelemetryEvent {
	newEvent := *oldEvent
	switch event := newEvent.Event.(type) {
	case *api.TelemetryEvent_Chargen:
		newChargen := *event.Chargen
		newEvent.Event.(*api.TelemetryEvent_Chargen).Chargen = &newChargen
	case *api.TelemetryEvent_Container:
		newContainer := *event.Container
		newEvent.Event.(*api.TelemetryEvent_Container).Container = &newContainer
	case *api.TelemetryEvent_File:
		newFile := *event.File
		newEvent.Event.(*api.TelemetryEvent_File).File = &newFile
	case *api.TelemetryEvent_KernelCall:
		newKernelCall := *event.KernelCall
		newEvent.Event.(*api.TelemetryEvent_KernelCall).KernelCall = &newKernelCall
	case *api.TelemetryEvent_Network:
		newNetwork := *event.Network
		newEvent.Event.(*api.TelemetryEvent_Network).Network = &newNetwork
	case *api.TelemetryEvent_Process:
		newProcess := *event.Process
		newEvent.Event.(*api.TelemetryEvent_Process).Process = &newProcess
	case *api.TelemetryEvent_Syscall:
		newSyscall := *event.Syscall
		newEvent.Event.(*api.TelemetryEvent_Syscall).Syscall = &newSyscall
	default:
		glog.Fatal("Unable to copy event: %+v", oldEvent)
	}
	return &newEvent
}
