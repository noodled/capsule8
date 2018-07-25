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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

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
	runtimeDir            string
	perfEventDir          string
	tracingDir            string
	dockerContainerDir    string
	ociContainerDir       string
	procFS                proc.FileSystem
	eventSourceController perf.EventSourceController
	cleanupFuncs          []func()
	cgroupNames           []string
}

// NewSensorOption is used to implement optional arguments for NewSensor.
// It must be exported, but it is not typically used directly.
type NewSensorOption func(*newSensorOptions)

// WithRuntimeDir is used to set the runtime state directory to use for the
// sensor.
func WithRuntimeDir(runtimeDir string) NewSensorOption {
	return func(o *newSensorOptions) {
		o.runtimeDir = runtimeDir
	}
}

// WithDockerContainerDir is used to set the directory to monitor for Docker
// container activity.
func WithDockerContainerDir(dockerContainerDir string) NewSensorOption {
	return func(o *newSensorOptions) {
		o.dockerContainerDir = dockerContainerDir
	}
}

// WithOciContainerDir is used to set the directory to monitor for OCI
// container activity.
func WithOciContainerDir(ociContainerDir string) NewSensorOption {
	return func(o *newSensorOptions) {
		o.ociContainerDir = ociContainerDir
	}
}

// WithProcFileSystem is used to set the proc.FileSystem to use. The system
// default will be used if one is not specified.
func WithProcFileSystem(procFS proc.FileSystem) NewSensorOption {
	return func(o *newSensorOptions) {
		o.procFS = procFS
	}
}

// WithEventSourceController is used to set the perf.EventSourceController to
// use. This is not used by the sensor itself, but passed through when a new
// EventMonitor is created.
func WithEventSourceController(controller perf.EventSourceController) NewSensorOption {
	return func(o *newSensorOptions) {
		o.eventSourceController = controller
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

// WithCleanupFunc is used to register a cleanup function that will be called
// when the sensor is stopped. Multiple cleanup functions may be registered,
// and will be called in the reverse order in which the were registered.
func WithCleanupFunc(cleanupFunc func()) NewSensorOption {
	return func(o *newSensorOptions) {
		o.cleanupFuncs = append(o.cleanupFuncs, cleanupFunc)
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

	// A reference to the event source controller in use.
	EventSourceController perf.EventSourceController

	// Runtime options configured during NewSensor, but not used until
	// later
	runtimeDir         string
	dockerContainerDir string
	ociContainerDir    string
	cgroupNames        []string

	// Cleanup functions to be run (in reverse order) when the sensor is
	// stopped.
	cleanupFuncs []func()
}

type queuedSamples struct {
	next    *queuedSamples
	samples []perf.EventMonitorSample
}

// NewSensor creates a new Sensor instance.
func NewSensor(options ...NewSensorOption) (*Sensor, error) {
	opts := newSensorOptions{
		runtimeDir:         config.Global.RunDir,
		dockerContainerDir: config.Sensor.DockerContainerDir,
		ociContainerDir:    config.Sensor.OciContainerDir,
		cgroupNames:        config.Sensor.CgroupName,
	}
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
			return nil, errors.New("Cannot resolve host proc filesystem")
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
		ID:                    sensorID,
		bootMonotimeNanos:     sys.CurrentMonotonicRaw(),
		perfEventDir:          opts.perfEventDir,
		tracingDir:            opts.tracingDir,
		ProcFS:                opts.procFS,
		eventMap:              newSafeSubscriptionMap(),
		EventSourceController: opts.eventSourceController,
		runtimeDir:            opts.runtimeDir,
		dockerContainerDir:    opts.dockerContainerDir,
		ociContainerDir:       opts.ociContainerDir,
		cleanupFuncs:          opts.cleanupFuncs,
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
	if err := os.MkdirAll(s.runtimeDir, 0700); err != nil {
		glog.Warningf("Couldn't mkdir %s: %v", s.runtimeDir, err)
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
		s.cleanupFuncs = append(s.cleanupFuncs, s.unmountTraceFS)
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
		} else {
			s.cleanupFuncs = append(s.cleanupFuncs,
				s.unmountPerfEventCgroupFS)
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

	if len(s.dockerContainerDir) > 0 {
		s.dockerMonitor = newDockerMonitor(s, s.dockerContainerDir)
		if s.dockerMonitor != nil {
			s.dockerMonitor.start()
		}
	}
	/* Temporarily disable the OCI monitor until a better means of
	   supporting it is found.
	if len(s.ociContainerDir) > 0 {
		s.ociMonitor = newOciMonitor(s, s.ociContainerDir)
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

	for x := len(s.cleanupFuncs) - 1; x >= 0; x-- {
		s.cleanupFuncs[x]()
	}
}

func (s *Sensor) mountTraceFS() error {
	dir := filepath.Join(s.runtimeDir, "tracing")
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
	dir := filepath.Join(s.runtimeDir, "perf_event")
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

func (s *Sensor) buildMonitorGroups() ([]string, []int, error) {
	var (
		cgroupList []string
		pidList    []int
		system     bool
	)

	cgroups := make(map[string]bool)
	for _, cgroup := range s.cgroupNames {
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
	eventMonitorOptions = append(eventMonitorOptions,
		perf.WithEventSourceController(s.EventSourceController))

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
	ok := true
	if s.kallsyms != nil {
		_, ok = s.kallsyms[symbol]
	}
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
	subscriptionID := atomic.AddUint64(&s.Metrics.Subscriptions, 1)

	// Use an empty dispatch function until Subscription.Run is called with
	// the real dispatch function to use. This is to avoid an extra branch
	// during dispatch to check for a nil dispatchFn. Since under normal
	// operation this case is impossible, it's a waste to add the check
	// when it's so easy to handle otherwise during the subscription
	// window.
	return &Subscription{
		sensor:         s,
		subscriptionID: subscriptionID,
		dispatchFn:     func(e TelemetryEvent) {},
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

		event, ok := esm.DecodedSample.(TelemetryEvent)
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
			containerInfo := event.CommonTelemetryEventData().Container
			if !s.containerFilter.Match(containerInfo) {
				continue
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
