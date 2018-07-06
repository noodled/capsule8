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

// This file implements a process information cache that uses a sensor's
// system-global EventMonitor to keep it up-to-date. The cache also monitors
// for runc container starts to identify the containerID for a given PID
// namespace. Process information gathered by the cache may be retrieved via
// the LookupTask and LookupTaskAndLeader methods.
//
// glog levels used:
//   10 = cache operation level tracing for debugging

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/capsule8/capsule8/pkg/sys/proc"

	"github.com/golang/glog"

	"golang.org/x/sys/unix"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var processExecEventTypes = expression.FieldTypeMap{
	"filename": expression.ValueTypeString,
}

var processForkEventTypes = expression.FieldTypeMap{
	"fork_child_pid": expression.ValueTypeSignedInt32,
	"fork_child_id":  expression.ValueTypeString,
}

var processExitEventTypes = expression.FieldTypeMap{
	"code":             expression.ValueTypeSignedInt32,
	"exit_status":      expression.ValueTypeUnsignedInt32,
	"exit_signal":      expression.ValueTypeUnsignedInt32,
	"exit_core_dumped": expression.ValueTypeBool,
}

var processUpdateEventTypes = expression.FieldTypeMap{
	"cwd": expression.ValueTypeString,
}

const taskReuseThreshold = int64(10 * time.Millisecond)

const (
	commitCredsAddress = "commit_creds"
	commitCredsArgs    = "usage=+0(%di):u64 " +
		"uid=+4(%di):u32 gid=+8(%di):u32 " +
		"suid=+12(%di):u32 sgid=+16(%di):u32 " +
		"euid=+20(%di):u32 egid=+24(%di):u32 " +
		"fsuid=+28(%di):u32 fsgid=+32(%di):u32"

	// Kernel versions 3.16 through 4.16 should all work with this symbol
	// and fetchargs. Older kernels will need to use attach_task_by_pid,
	// below.
	//
	// static ssize_t __cgroup_procs_write(struct kernfs_open_file *of,
	//      char *buf, size_t nbytes, loff_t off, bool threadgroup)
	// container_id comes from of->file->f_path.dentry->d_parent->d_name.name
	cgroupProcsWriteAddress = "__cgroup_procs_write"
	cgroupProcsWriteArgs    = "container_id=+0(+40(+24(+24(+8(%di))))):string " +
		"buf=+0(%si):string threadgroup=%r8:s32"

	cgroup1ProcsWriteAddress = "__cgroup1_procs_write"
	cgroup1ProcsWriteArgs    = "container_id=+0(+40(+24(+24(+8(%di))))):string " +
		"buf=+0(%si):string threadgroup=%r8:s32"

	// static int attach_task_by_pid(struct cgroup *cgrp, u64 pid, bool threadgroup)
	attachTaskByPid      = "attach_task_by_pid"
	attachTaskByPidArgs1 = "container_id=+0(+56(+56(%di))):string pid=%si:u64 threadgroup=%dx:u32" // RHEL 6: 2.6.32
	attachTaskByPidArgs2 = "container_id=+0(+40(+72(%di))):string pid=%si:u64 threadgroup=%dx:u32" // 3.5.x-3.14.x
	attachTaskByPidArgs3 = "container_id=+0(+16(+64(%di))):string pid=%si:u64 threadgroup=%dx:u32" // 3.15.x

	execveArgCount = 6

	doExecveAddress    = "do_execve"
	doExecveArgs       = "filename=+0(+0(%di)):string "
	doExecveatAddress  = "do_execveat"
	doExecveatArgs     = "filename=+0(+0(%si)):string "
	sysExecveAddress   = "sys_execve"
	sysExecveArgs      = "filename=+0(%di):string "
	sysExecveatAddress = "sys_execveat"
	sysExecveatArgs    = "filename=%0(%si):string "

	doExitAddress = "do_exit"
	doExitArgs    = "code=%di:s64"

	doForkAddress   = "do_fork"
	doForkFetchargs = "clone_flags=%di:u64"

	// This is used for tracking current working directory. It's a
	// a kretprobe that's used to trigger a lookup in /proc to get the
	// needed data.
	doSetFsPwd = "set_fs_pwd"
)

// Cred contains task credential information
type Cred struct {
	// UID is the real UID
	UID uint32
	// GID is the real GID
	GID uint32
	// EUID is the effective UID
	EUID uint32
	// EGID is the effective GID
	EGID uint32
	// SUID is the saved UID
	SUID uint32
	// SGID is the saved GID
	SGID uint32
	// FSUID is the UID for filesystem operations
	FSUID uint32
	// FSGID is the GID for filesystem operations
	FSGID uint32
}

var rootCredentials = Cred{}

func newCredentials(
	uid, euid, suid, fsuid uint32,
	gid, egid, sgid, fsgid uint32,
) *Cred {
	if uid == 0 && euid == 0 && suid == 0 && fsuid == 0 {
		if gid == 0 && egid == 0 && sgid == 0 && fsgid == 0 {
			return &rootCredentials
		}
	}

	return &Cred{
		UID:   uid,
		GID:   gid,
		EUID:  euid,
		EGID:  egid,
		SUID:  suid,
		SGID:  sgid,
		FSUID: fsuid,
		FSGID: fsgid,
	}
}

const cloneEventThreshold = uint64(100 * time.Millisecond)

type cloneEvent struct {
	timestamp uint64

	// Set by the parent
	cloneFlags uint64

	// Set by the child
	childPid  int
	childComm string
}

func (c *cloneEvent) isExpired(t uint64) bool {
	if c == nil {
		return true
	}
	var delta uint64
	if c.timestamp < t {
		delta = t - c.timestamp
	} else {
		delta = c.timestamp - t
	}
	if delta > cloneEventThreshold {
		fmt.Printf("cloneevent delta %d\n", delta)
	}
	return delta > cloneEventThreshold
}

// Task represents a schedulable task. All Linux tasks are uniquely identified
// at a given time by their PID, but those PIDs may be reused after hitting the
// maximum PID value.
type Task struct {
	// PID is the kernel's internal process identifier, which is equivalent
	// to the TID in userspace.
	PID int

	// TGID is the kernel's internal thread group identifier, which is
	// equivalent to the PID in userspace. All threads within a process
	// have differing PIDs, but all share the same TGID. The thread group
	// leader process's PID will be the same as its TGID.
	TGID int

	// Command is the kernel's comm field, which is initialized to the
	// first 15 characters of the basename of the executable being run.
	// It is also set via pthread_setname_np(3) and prctl(2) PR_SET_NAME.
	// It is always NULL-terminated and no longer than 16 bytes (including
	// NUL byte).
	Command string

	// CommandLine is the command-line used when the process was exec'd via
	// execve(). It is composed of the first 6 elements of argv. It may
	// not be complete if argv contained more than 6 elements.
	CommandLine []string

	// Creds are the credentials (uid, gid) for the task. This is kept
	// up-to-date by recording changes observed via a kprobe on
	// commit_creds().
	Creds *Cred

	// ContainerID is the ID of the container to which the task belongs,
	// if any.
	ContainerID string

	// ContainerInfo is a pointer to the cached container information for
	// the container to which the task belongs, if any.
	ContainerInfo *ContainerInfo

	// StartTime is the time at which a task started.
	StartTime int64

	// ExitTime is the time at which a task exited.
	ExitTime int64

	// ProcessID is a unique ID for the task.
	ProcessID string

	// CWD is the current working directory for the task. Tasks within a
	// process can each have their own independent CWD.
	CWD string

	// parent is an internal reference to the parent of this task, which
	// could be either the thread group leader or another process. Use
	// Parent() to get the parent of a container.
	parent *Task

	// pendingClone is used internally for tracking information about a
	// task clone executed by the clone(2) system call. In kernels >= 3.9
	// this is not necessary
	pendingClone *cloneEvent
}

var rootTask = Task{}

func newTask(pid int) *Task {
	return &Task{
		PID: pid,
	}
}

var sensorPID = os.Getpid()

// IsSensor returns true if the task belongs to the sensor process.
func (t *Task) IsSensor() bool {
	return t.TGID == sensorPID
}

// Leader returns a reference to a task's leader task.
func (t *Task) Leader() *Task {
	if t.PID == t.TGID {
		return t
	}
	return t.Parent()
}

// Parent returns a reference to a task's parent task.
func (t *Task) Parent() *Task {
	if t.parent == nil {
		// t.parent may not be set yet if events arrive out of order.
		if t.TGID != 0 {
			glog.Fatalf("Internal error: t.PID == %d && t.TGID == %d && t.parent == nil", t.PID, t.TGID)
		}
		// We don't know anything about the parent, so return this task
		// as the parent. Don't store the reference, though.
		return t
	}
	return t.parent
}

// Update updates a task instance with new data. It returns true if any data
// was actually changed.
func (t *Task) Update(
	changes map[string]interface{},
	changeTime uint64,
	procFS proc.FileSystem,
) bool {
	dataChanged := false
	changedContainerInfo := false
	changedPID := false
	changedStartTime := false

	s := reflect.ValueOf(t).Elem()
	st := s.Type()
	for i := st.NumField() - 1; i >= 0; i-- {
		f := st.Field(i)
		if !unicode.IsUpper(rune(f.Name[0])) {
			continue
		}
		v, ok := changes[f.Name]
		if !ok {
			continue
		}
		if !reflect.TypeOf(v).AssignableTo(f.Type) {
			glog.Fatalf("Cannot assign %v to %s %v",
				v, f.Name, f.Type)
		}

		// Assume field types that are not compareable always change
		// Examples of uncompareable types: []string (e.g. CommandLine)
		if !reflect.TypeOf(v).Comparable() ||
			s.Field(i).Interface() != v {
			dataChanged = true
			s.Field(i).Set(reflect.ValueOf(v))

			switch f.Name {
			case "PID", "TGID":
				changedPID = true
			case "StartTime":
				changedStartTime = true
			case "ContainerID":
				// Invalidate ContainerInfo if it hasn't
				// already been changed in this update.
				if !changedContainerInfo {
					t.ContainerInfo = nil
				}
			case "ContainerInfo":
				changedContainerInfo = true
			}
		}
	}

	if changedPID || changedStartTime {
		if !changedStartTime {
			var err error
			t.StartTime, err = procFS.TaskStartTime(t.TGID, t.PID)
			if err != nil {
				t.StartTime = int64(changeTime)
			}
		}
		if t.StartTime > 0 {
			t.ProcessID, _ = procFS.TaskUniqueID(
				t.TGID, t.PID, t.StartTime)
		} else {
			t.ProcessID = ""
		}
	}

	return dataChanged
}

type taskCache interface {
	LookupTask(int) *Task
}

type arrayTaskCache struct {
	entries []*Task
}

func newArrayTaskCache(size uint) *arrayTaskCache {
	return &arrayTaskCache{
		entries: make([]*Task, size),
	}
}

func (c *arrayTaskCache) LookupTask(pid int) *Task {
	if pid <= 0 || pid > len(c.entries) {
		glog.Fatalf("Invalid pid for lookup: %d", pid)
	}

	var t *Task
	for {
		var old *Task

		t = c.entries[pid-1]
		if t != nil {
			if t.ExitTime == 0 ||
				sys.CurrentMonotonicRaw()-t.ExitTime <
					taskReuseThreshold {
				break
			}
			old = t
		}
		t = newTask(pid)
		if atomic.CompareAndSwapPointer(
			(*unsafe.Pointer)(unsafe.Pointer(&c.entries[pid-1])),
			unsafe.Pointer(old),
			unsafe.Pointer(t)) {
			break
		}
	}
	glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	return t
}

type mapTaskCache struct {
	sync.Mutex
	entries map[int]*Task
}

func newMapTaskCache(size uint) *mapTaskCache {
	// The size here is likely to be quite large, so we don't really want
	// to size the map to it initially. On the other hand, we don't want
	// to let the map grow naturally using Go defaults, because we assume
	// that we will have a fairly large number of tasks.
	return &mapTaskCache{
		entries: make(map[int]*Task, size/4),
	}
}

func (c *mapTaskCache) LookupTask(pid int) *Task {
	if pid <= 0 {
		glog.Fatalf("Invalid pid for lookup: %d", pid)
	}

	c.Lock()
	t, ok := c.entries[pid]
	if !ok || (t.ExitTime != 0 &&
		sys.CurrentMonotonicRaw()-t.ExitTime >= taskReuseThreshold) {
		t = newTask(pid)
		c.entries[pid] = t
	}
	c.Unlock()
	glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	return t
}

// ProcessInfoCache is an object that caches process information. It is
// maintained automatically via an existing sensor object.
type ProcessInfoCache struct {
	cache taskCache

	sensor *Sensor

	// These are external event IDs registered with the sensor's event
	// monitor instance. The cache will enqueue these events as appropriate
	// as the cache is updated.
	ProcessExecEventID   uint64 // api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC
	ProcessForkEventID   uint64 // api.ProcessEventType_PROCESS_EVENT_TYPE_FORK
	ProcessExitEventID   uint64 // api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT
	ProcessUpdateEventID uint64 // api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE

	startLock  sync.Mutex
	startQueue []scannerDeferredAction
	started    bool
}

type scannerDeferredAction func()

// NewProcessInfoCache creates a new process information cache object. An
// existing sensor object is required in order for the process info cache to
// able to install its probes to monitor the system to maintain the cache.
func NewProcessInfoCache(sensor *Sensor) *ProcessInfoCache {
	cache := &ProcessInfoCache{
		sensor: sensor,
	}

	maxPID := sensor.ProcFS.MaxPID()
	if maxPID > config.Sensor.ProcessInfoCacheSize {
		cache.cache = newMapTaskCache(maxPID)
	} else {
		cache.cache = newArrayTaskCache(maxPID)
	}

	var err error
	cache.ProcessExecEventID, err = sensor.Monitor.RegisterExternalEvent(
		"PROCESS_EXEC", cache.decodeProcessExecEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ProcessForkEventID, err = sensor.Monitor.RegisterExternalEvent(
		"PROCESS_FORK", cache.decodeProcessForkEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ProcessExitEventID, err = sensor.Monitor.RegisterExternalEvent(
		"PROCESS_EXIT", cache.decodeProcessExitEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ProcessUpdateEventID, err = sensor.Monitor.RegisterExternalEvent(
		"PROCESS_UPDATE", cache.decodeProcessUpdateEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	// Register with the sensor's global event monitor...
	eventName := "task/task_newtask"
	_, err = sensor.Monitor.RegisterTracepoint(eventName,
		cache.decodeNewTask,
		perf.WithEventEnabled())
	if err != nil {
		eventName = doForkAddress
		_, err = sensor.RegisterKprobe(eventName, false,
			doForkFetchargs, cache.decodeDoFork,
			perf.WithEventEnabled())
		if err != nil {
			eventName = "_" + eventName
			_, err = sensor.RegisterKprobe(eventName, false,
				doForkFetchargs, cache.decodeDoFork,
				perf.WithEventEnabled())
			if err != nil {
				glog.Fatalf("Couldn't register kprobe %s: %s",
					eventName, err)
			}
		}

		eventName = "sched/sched_process_fork"
		_, err = sensor.Monitor.RegisterTracepoint(eventName,
			cache.decodeSchedProcessFork,
			perf.WithEventEnabled())
	}

	eventName = doExitAddress
	_, err = sensor.RegisterKprobe(eventName, false,
		doExitArgs, cache.decodeDoExit,
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Couldn't register event %s: %s", eventName, err)
	}

	// Attach kprobe on commit_creds to capture task privileges
	_, err = sensor.RegisterKprobe(commitCredsAddress, false,
		commitCredsArgs, cache.decodeCommitCreds,
		perf.WithEventEnabled())

	// Attach kretprobe on set_fs_pwd to track working directories
	_, err = sensor.RegisterKprobe(doSetFsPwd, true,
		"", cache.decodeDoSetFsPwd,
		perf.WithEventEnabled())

	// Attach a probe to capture exec events in the kernel. Different
	// kernel versions require different probe attachments, so try to do
	// the best that we can here. We may end up getting duplicate events,
	// which is ok.
	_, err = sensor.RegisterKprobe(
		sysExecveAddress, false,
		sysExecveArgs+makeExecveFetchArgs("si"),
		cache.decodeExecve,
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Couldn't register event %s: %s",
			sysExecveAddress, err)
	}
	_, _ = sensor.RegisterKprobe(
		doExecveAddress, false,
		doExecveArgs+makeExecveFetchArgs("si"),
		cache.decodeExecve,
		perf.WithEventEnabled())

	_, err = sensor.RegisterKprobe(
		sysExecveatAddress, false,
		sysExecveatArgs+makeExecveFetchArgs("dx"),
		cache.decodeExecve,
		perf.WithEventEnabled())
	if err == nil {
		_, _ = sensor.RegisterKprobe(
			doExecveatAddress, false,
			makeExecveFetchArgs("dx"), cache.decodeExecve,
			perf.WithEventEnabled())
	}

	if err = cache.installCgroupMonitor(); err != nil {
		glog.Fatalf("Could not install cgroup monitoring: %v", err)
	}

	return cache
}

func makeExecveFetchArgs(reg string) string {
	parts := make([]string, execveArgCount)
	for i := 0; i < execveArgCount; i++ {
		parts[i] = fmt.Sprintf("argv%d=+0(+%d(%%%s)):string", i, i*8, reg)
	}
	return strings.Join(parts, " ")
}

// Start enables the process cache by scanning the /proc filesystem to learn
// about existing processes and enable monitoring once that is done.
func (pc *ProcessInfoCache) Start() {
	if pc.started {
		glog.Fatal("Illegal second call to ProcessInfoCache.Start()")
	}

	// Scan the proc filesystem to learn about all existing tasks.
	if err := pc.scanProcFilesystem(); err != nil {
		glog.Fatal(err)
	}

	pc.startLock.Lock()
	for len(pc.startQueue) > 0 {
		queue := pc.startQueue
		pc.startQueue = nil
		pc.startLock.Unlock()
		for _, f := range queue {
			f()
		}
		pc.startLock.Lock()
	}
	pc.started = true
	pc.startLock.Unlock()
}

func (pc *ProcessInfoCache) cacheTaskFromProc(tgid, pid int) error {
	var s struct {
		Name string   `Name`
		PID  int      `Pid`
		PPID int      `PPid`
		TGID int      `Tgid`
		UID  []uint32 `Uid`
		GID  []uint32 `Gid`
	}
	procFS := pc.sensor.ProcFS
	err := procFS.ReadTaskStatus(tgid, pid, &s)
	if err != nil {
		return fmt.Errorf("Couldn't read pid %d status: %s",
			pid, err)
	}

	t := pc.cache.LookupTask(s.PID)
	t.TGID = s.TGID
	t.Command = s.Name
	t.Creds = newCredentials(s.UID[0], s.UID[1], s.UID[2], s.UID[3],
		s.GID[0], s.GID[1], s.GID[2], s.GID[3])
	t.StartTime, err = procFS.TaskStartTime(tgid, pid)
	if err != nil {
		t.StartTime = sys.CurrentMonotonicRaw()
	}
	t.ProcessID, _ = procFS.TaskUniqueID(t.TGID, t.PID, t.StartTime)
	if t.PID != t.TGID {
		t.parent = pc.cache.LookupTask(t.TGID)
	} else {
		if s.PPID == 0 && (t.PID == 1 || s.Name == "kthreadd") {
			t.parent = &rootTask
		} else {
			t.parent = pc.cache.LookupTask(s.PPID)
		}
		// Failures here can be ignored; the task has completed while
		// we've been processing it.
		t.CommandLine, _ = procFS.ProcessCommandLine(t.TGID)
		t.CWD, _ = procFS.TaskCWD(t.TGID, t.PID)
		t.ContainerID, _ = procFS.ProcessContainerID(tgid)
	}

	return nil
}

func (pc *ProcessInfoCache) scanProcFilesystem() error {
	return pc.sensor.ProcFS.WalkTasks(func(tgid, pid int) bool {
		pc.cacheTaskFromProc(tgid, pid)
		return true
	})
}

func (pc *ProcessInfoCache) installCgroupMonitor() error {
	// All kernel versions have the "cgroup_procs_write" symbol, which we
	// will use to determine whether cgroup monitoring is possible at all.
	// Structs are different in different kernel versions, though, so we
	// have to do more work to pick out the right symbol and fetchargs.
	if !pc.sensor.IsKernelSymbolAvailable("cgroup_procs_write") {
		glog.Info("CGROUP monitoring disabled: kernel compiled without CGROUPS support")
		return nil
	}

	var (
		eventName, fetchArgs   string
		eventName2, fetchArgs2 string
	)

	// attach_task_by_pid exists in kernel versions < 3.16
	if pc.sensor.IsKernelSymbolAvailable(attachTaskByPid) {
		eventName = attachTaskByPid

		// The structure of struct cgroup changes in 3.5. The symbol
		// cgroup_add_files exists in kernel versions < 3.5.
		// The structure of struct cgroup changes again in 3.15. The
		// symbol cgroup_taskset_size exists in kernel versions < 3.15.
		if pc.sensor.IsKernelSymbolAvailable("cgroup_add_files") {
			fetchArgs = attachTaskByPidArgs1
		} else if pc.sensor.IsKernelSymbolAvailable("cgroup_taskset_size") {
			fetchArgs = attachTaskByPidArgs2
		} else {
			fetchArgs = attachTaskByPidArgs3
		}
	} else if pc.sensor.IsKernelSymbolAvailable(cgroupProcsWriteAddress) {
		eventName = cgroupProcsWriteAddress
		fetchArgs = cgroupProcsWriteArgs
	} else if pc.sensor.IsKernelSymbolAvailable(cgroup1ProcsWriteAddress) {
		eventName = cgroup1ProcsWriteAddress
		fetchArgs = cgroup1ProcsWriteArgs
		eventName2 = "cgroup_procs_write"
		fetchArgs2 = cgroupProcsWriteArgs
	} else {
		return errors.New("Known cgroup symbols not found")
	}

	_, err := pc.sensor.RegisterKprobe(eventName, false,
		fetchArgs, pc.decodeCgroupProcsWrite,
		perf.WithEventEnabled())
	if err != nil {
		return fmt.Errorf("%s: %v", eventName, err)
	}

	if eventName2 != "" {
		_, err := pc.sensor.RegisterKprobe(eventName2, false,
			fetchArgs2, pc.decodeCgroupProcsWrite,
			perf.WithEventEnabled())
		if err != nil {
			return fmt.Errorf("%s: %v", eventName2, err)
		}
	}

	return nil
}

// LookupTask finds the task information for the given PID.
func (pc *ProcessInfoCache) LookupTask(pid int) *Task {
	return pc.cache.LookupTask(pid)
}

// LookupTaskAndLeader finds the task information for both a given PID and the
// thread group leader.
func (pc *ProcessInfoCache) LookupTaskAndLeader(pid int) (*Task, *Task) {
	t := pc.cache.LookupTask(pid)
	return t, t.Leader()
}

// LookupTaskContainerInfo returns the container info for a task, possibly
// consulting the sensor's container cache and updating the task cached
// information.
func (pc *ProcessInfoCache) LookupTaskContainerInfo(t *Task) *ContainerInfo {
	if t.PID != t.TGID {
		t = t.Parent()
	}
	if i := t.ContainerInfo; i != nil {
		return t.ContainerInfo
	}

	if ID := t.ContainerID; len(ID) > 0 {
		if i := pc.sensor.ContainerCache.LookupContainer(ID, true); i != nil {
			t.ContainerInfo = i
			return i
		}
	}

	return nil
}

func (pc *ProcessInfoCache) maybeDeferAction(f func()) {
	if !pc.started {
		pc.startLock.Lock()
		if !pc.started {
			pc.startQueue = append(pc.startQueue, f)
			pc.startLock.Unlock()
			return
		}
		pc.startLock.Unlock()
	}

	f()
}

func (pc *ProcessInfoCache) newProcessEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
	eventType api.ProcessEventType,
) (*api.TelemetryEvent, error) {
	event := pc.sensor.NewEventFromSample(sample, data)
	if event == nil {
		return nil, nil
	}

	pev := &api.ProcessEvent{
		Type: eventType,
	}

	switch eventType {
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
		pev.ExecFilename = data["filename"].(string)
		pev.ExecCommandLine = data["exec_command_line"].([]string)
	case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
		pev.ForkChildPid = data["fork_child_pid"].(int32)
		pev.ForkChildId = data["fork_child_id"].(string)
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
		pev.ExitCode = data["code"].(int32)
		pev.ExitStatus = data["exit_status"].(uint32)
		pev.ExitSignal = data["exit_signal"].(uint32)
		pev.ExitCoreDumped = data["exit_core_dumped"].(bool)
	case api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE:
		pev.UpdateCwd = data["cwd"].(string)
	}

	event.Event = &api.TelemetryEvent_Process{
		Process: pev,
	}
	return event, nil
}

func (pc *ProcessInfoCache) decodeProcessExecEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return pc.newProcessEvent(sample, data,
		api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC)
}

func (pc *ProcessInfoCache) decodeProcessForkEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return pc.newProcessEvent(sample, data,
		api.ProcessEventType_PROCESS_EVENT_TYPE_FORK)
}

func (pc *ProcessInfoCache) decodeProcessExitEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return pc.newProcessEvent(sample, data,
		api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT)
}

func (pc *ProcessInfoCache) decodeProcessUpdateEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return pc.newProcessEvent(sample, data,
		api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE)
}

func sampleIDFromSample(sample *perf.SampleRecord) perf.SampleID {
	return perf.SampleID{
		Time: sample.Time,
		PID:  sample.Pid,
		TID:  sample.Tid,
		CPU:  sample.CPU,
	}
}

func (pc *ProcessInfoCache) handleSysClone(
	parentTask, parentLeader, childTask *Task,
	cloneFlags uint64,
	childComm string,
	sample *perf.SampleRecord,
) {
	changes := map[string]interface{}{
		"Command": childComm,
		"Creds":   parentTask.Creds,
	}

	if (cloneFlags & CLONE_THREAD) != 0 {
		changes["TGID"] = parentTask.PID
	} else {
		// This is a new thread group leader, tgid is the new pid
		changes["TGID"] = childTask.PID
		changes["ContainerID"] = parentLeader.ContainerID
		changes["ContainerInfo"] = parentLeader.ContainerInfo
	}

	// This must be done before filling in eventData, because otherwise
	// childTask.ProcessID won't be set yet.
	childTask.parent = parentTask
	childTask.Update(changes, sample.Time, pc.sensor.ProcFS)

	eventData := map[string]interface{}{
		"__task__":       parentTask,
		"fork_child_pid": int32(childTask.PID),
		"fork_child_id":  childTask.ProcessID,
	}
	pc.sensor.Monitor.EnqueueExternalSample(
		pc.ProcessForkEventID,
		sampleIDFromSample(sample),
		eventData)
}

func (pc *ProcessInfoCache) decodeNewTask(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	parentPid := int(data["common_pid"].(int32))
	childPid := int(data["pid"].(int32))
	cloneFlags := data["clone_flags"].(uint64)
	childComm := commToString(data["comm"].([]interface{}))

	pc.maybeDeferAction(func() {
		parentTask, parentLeader := pc.LookupTaskAndLeader(parentPid)
		childTask := pc.LookupTask(childPid)

		pc.handleSysClone(parentTask, parentLeader, childTask,
			cloneFlags, childComm, sample)
	})

	return nil, nil
}

// decodeDoExit marks a task as having exited. The time of the exit
// is noted so that the task can be safely reused later. Don't delete it from
// the cache, because out-of-order events could cause it to be recreated and
// then when the pid is reused by the kernel later, it'll contain stale data.
func (pc *ProcessInfoCache) decodeDoExit(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))
	exitCode := data["code"].(int64)

	changes := map[string]interface{}{
		"ExitTime": sys.CurrentMonotonicRaw(),
	}

	ws := unix.WaitStatus(exitCode)
	eventData := map[string]interface{}{
		"code": int32(exitCode),
	}

	if ws.Exited() {
		eventData["exit_status"] = uint32(ws.ExitStatus())
		eventData["exit_signal"] = uint32(0)
		eventData["exit_core_dumped"] = false
	} else {
		eventData["exit_status"] = uint32(0)
		eventData["exit_signal"] = uint32(ws.Signal())
		eventData["exit_core_dumped"] = ws.CoreDump()
	}

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)
		t.Update(changes, sample.Time, pc.sensor.ProcFS)
		eventData["__task__"] = t
		pc.sensor.Monitor.EnqueueExternalSample(
			pc.ProcessExitEventID,
			sampleIDFromSample(sample),
			eventData)
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeCommitCreds(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))

	if usage := data["usage"].(uint64); usage == 0 {
		glog.Fatal("Received commit_creds with zero usage")
	}

	changes := map[string]interface{}{
		"Creds": &Cred{
			UID:   data["uid"].(uint32),
			GID:   data["gid"].(uint32),
			EUID:  data["euid"].(uint32),
			EGID:  data["egid"].(uint32),
			SUID:  data["suid"].(uint32),
			SGID:  data["sgid"].(uint32),
			FSUID: data["fsuid"].(uint32),
			FSGID: data["fsgid"].(uint32),
		},
	}

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)
		t.Update(changes, sample.Time, pc.sensor.ProcFS)
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeDoSetFsPwd(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)
		cwd, err := pc.sensor.ProcFS.TaskCWD(t.TGID, t.PID)
		if err == nil && cwd != t.CWD {
			glog.V(10).Infof("CWD(%d) = %s", t.PID, cwd)
			changes := map[string]interface{}{
				"CWD": cwd,
			}
			t.Update(changes, sample.Time, pc.sensor.ProcFS)

			eventData := map[string]interface{}{
				"__task__": t,
				"cwd":      t.CWD,
			}
			pc.sensor.Monitor.EnqueueExternalSample(
				pc.ProcessUpdateEventID,
				sampleIDFromSample(sample),
				eventData)

		}
	})

	return nil, nil
}

// decodeDoExecve decodes sys_execve() and sys_execveat() events to obtain the
// command-line for the process.
func (pc *ProcessInfoCache) decodeExecve(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))
	commandLine := make([]string, 0, execveArgCount)
	for i := 0; i < execveArgCount; i++ {
		s := data[fmt.Sprintf("argv%d", i)].(string)
		if len(s) == 0 {
			break
		}
		commandLine = append(commandLine, s)
	}

	changes := map[string]interface{}{
		"CommandLine": commandLine,
	}

	eventData := map[string]interface{}{
		"filename":          data["filename"].(string),
		"exec_command_line": commandLine,
	}

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)
		t.Update(changes, sample.Time, pc.sensor.ProcFS)
		eventData["__task__"] = t
		pc.sensor.Monitor.EnqueueExternalSample(
			pc.ProcessExecEventID,
			sampleIDFromSample(sample),
			eventData)
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeDoFork(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))
	cloneFlags := data["clone_flags"].(uint64)

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)

		if t.pendingClone.isExpired(sample.Time) {
			t.pendingClone = &cloneEvent{
				timestamp:  sample.Time,
				cloneFlags: cloneFlags,
			}
		} else {
			c := t.pendingClone
			t.pendingClone = nil

			childTask := pc.LookupTask(c.childPid)
			pc.handleSysClone(t, t.Leader(), childTask,
				cloneFlags, c.childComm, sample)
		}
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeSchedProcessFork(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	parentPid := int(data["parent_pid"].(int32))
	childPid := int(data["child_pid"].(int32))
	childComm := commToString(data["child_comm"].([]interface{}))

	pc.maybeDeferAction(func() {
		parentTask, parentLeader := pc.LookupTaskAndLeader(parentPid)
		if parentTask.pendingClone.isExpired(sample.Time) {
			parentTask.pendingClone = &cloneEvent{
				timestamp: sample.Time,
				childPid:  childPid,
				childComm: childComm,
			}
		} else {
			c := parentTask.pendingClone
			parentTask.pendingClone = nil

			childTask := pc.LookupTask(childPid)
			pc.handleSysClone(parentTask, parentLeader, childTask,
				c.cloneFlags, childComm, sample)
		}
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeCgroupProcsWrite(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	// We're looking for container IDs, which are normally hex encoded
	// sha256 hashes. Basically just ensure that we've got exactly 64
	// characters. That should be good enough for now.
	containerID := data["container_id"].(string)
	if len(containerID) != 64 {
		return nil, nil
	}

	var (
		pid         int
		threadgroup bool
	)

	if buf, ok := data["buf"].(string); ok {
		buf = strings.TrimSpace(buf)
		if v, err := strconv.ParseInt(buf, 10, 32); err == nil {
			pid = int(v)
		} else {
			// If there's an error parsing data written to this file, we
			// want to know about it so that we can deal with it. Use a
			// high logging level to ensure that.
			glog.Warning("Error parsing pid written to cgroup.procs: %v", err)
			return nil, nil
		}
	} else if v, ok := data["tgid"].(uint64); ok {
		pid = int(v)
		threadgroup = true
	} else if v, ok := data["pid"].(uint64); ok {
		pid = int(v)
		threadgroup = false
	}
	if v, ok := data["threadgroup"].(int32); ok && v != 0 {
		threadgroup = true
	}

	pc.maybeDeferAction(func() {
		task, leader := pc.LookupTaskAndLeader(int(pid))
		if threadgroup {
			task = leader
		}

		// This event fires once for each cgroup a task is entered
		// into, which typically 13 times, so try to minimize the
		// amount of work done
		if task.ContainerID == containerID {
			return
		}

		glog.V(10).Infof("containerID(%d) = %s", task.PID, containerID)
		changes := map[string]interface{}{
			"ContainerID": containerID,
		}
		task.Update(changes, sample.Time, pc.sensor.ProcFS)
	})

	return nil, nil
}

func commToString(comm []interface{}) string {
	s := make([]byte, len(comm))
	for i, c := range comm {
		switch c := c.(type) {
		case int8:
			s[i] = byte(c)
		case uint8:
			// Kernel 2.6.32 erroneously reports unsigned
			s[i] = byte(c)
		}
		if s[i] == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

func rewriteProcessEventFilter(pef *api.ProcessEventFilter) {
	switch pef.Type {
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
		if pef.ExecFilename != nil {
			newExpr := expression.Equal(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilename.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilename = nil
			pef.ExecFilenamePattern = nil
		} else if pef.ExecFilenamePattern != nil {
			newExpr := expression.Like(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilenamePattern.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilenamePattern = nil
		}
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
		if pef.ExitCode != nil {
			newExpr := expression.Equal(
				expression.Identifier("code"),
				expression.Value(pef.ExitCode.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExitCode = nil
		}
	}
}

func registerProcessEvents(
	sensor *Sensor,
	subscr *subscription,
	events []*api.ProcessEventFilter,
) {
	var (
		filters       [5]*api.Expression
		subscriptions [5]*eventSink
		wildcards     [5]bool
	)

	for _, pef := range events {
		// Translate deprecated fields into an expression
		rewriteProcessEventFilter(pef)

		t := pef.Type
		if t < 1 || t > api.ProcessEventType(len(subscriptions)-1) {
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("ProcessEventType %d is invalid", t))
			continue
		}

		if subscriptions[t] == nil {
			var (
				eventID uint64
				types   expression.FieldTypeMap
			)

			switch t {
			case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
				eventID = sensor.ProcessCache.ProcessExecEventID
				types = processExecEventTypes
			case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
				eventID = sensor.ProcessCache.ProcessForkEventID
				types = processForkEventTypes
			case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
				eventID = sensor.ProcessCache.ProcessExitEventID
				types = processExitEventTypes
			case api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE:
				eventID = sensor.ProcessCache.ProcessUpdateEventID
				types = processUpdateEventTypes
			}
			subscriptions[t], _ =
				subscr.addEventSink(eventID, nil, types)
		}
		if pef.FilterExpression == nil {
			wildcards[t] = true
			filters[t] = nil
		} else if !wildcards[t] {
			filters[t] = expression.LogicalOr(
				filters[t],
				pef.FilterExpression)
		}
	}

	for t, s := range subscriptions {
		if filters[t] == nil {
			// No filter, no problem
			continue
		}

		expr, err := expression.NewExpression(filters[t])
		if err != nil {
			// Bad filter. Remove subscription
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("Invalid process filter expression: %v", err))
			subscr.removeEventSink(s)
			continue
		}

		switch api.ProcessEventType(t) {
		case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
			err = expr.Validate(processExecEventTypes)
		case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
			err = expr.Validate(processForkEventTypes)
		case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
			err = expr.Validate(processExitEventTypes)
		case api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE:
			err = expr.Validate(processUpdateEventTypes)
		}
		if err != nil {
			// Bad filter. Remove subscription
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("Invalid process filter expression: %v", err))
			subscr.removeEventSink(s)
			continue
		}

		s.filter = expr
	}
}
