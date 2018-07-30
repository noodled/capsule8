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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"
)

func TestNewCredentials(t *testing.T) {
	assert.Exactly(t, &rootCredentials, newCredentials(0, 0, 0, 0, 0, 0, 0, 0))

	expected := &Cred{1000, 5000, 2000, 6000, 3000, 7000, 4000, 8000}
	actual := newCredentials(1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000)
	assert.Equal(t, expected, actual)
}

func TestCloneEvent(t *testing.T) {
	var e *cloneEvent

	// A nil cloneEvent should return true to indicate that it is expired.
	assert.True(t, e.isExpired(uint64(sys.CurrentMonotonicRaw())))

	// Because clone related events can come out of order, a cloneEvent is
	// considered expired if its timestamp is +/- the current time by a
	// threshold constant (cloneEventThreshold = 100ms)
	e = &cloneEvent{timestamp: uint64(sys.CurrentMonotonicRaw())}
	assert.False(t, e.isExpired(e.timestamp+cloneEventThreshold/2))
	assert.False(t, e.isExpired(e.timestamp-cloneEventThreshold/2))
	assert.True(t, e.isExpired(e.timestamp+cloneEventThreshold*2))
	assert.True(t, e.isExpired(e.timestamp-cloneEventThreshold*2))
}

func TestTask(t *testing.T) {
	procFS, err := procfs.NewFileSystem("testdata")
	require.NoError(t, err)

	task := newTask(sensorPID)
	task.TGID = task.PID
	assert.True(t, task.IsSensor())

	task = newTask(1467)
	task.TGID = task.PID
	assert.False(t, task.IsSensor())

	parentTask := newTask(1231)
	parentTask.TGID = parentTask.PID
	assert.Equal(t, parentTask, parentTask.Leader())

	task.parent = parentTask
	task.TGID = parentTask.PID
	assert.Equal(t, parentTask, task.Leader())

	// Handling out of order events ... if task.parent is nil, the return
	// should be task. In this case, TGID must also be nil, but we can't
	// test for that, because glog.Fatal cannot be caught
	task.parent = nil
	task.TGID = 0
	assert.Equal(t, task, task.Parent())

	task = &Task{}
	changes := map[string]interface{}{
		"parent": parentTask, // this cannot be set via Task.Update
		"PID":    int(1467),
		"TGID":   parentTask.PID,
	}
	changeTime := uint64(2938475)
	b := task.Update(changes, changeTime, procFS)
	assert.True(t, b)
	assert.Nil(t, task.parent)
	assert.Equal(t, int(task.PID), task.PID)
	assert.Equal(t, parentTask.PID, task.TGID)
	assert.NotZero(t, task.ProcessID)
	assert.Equal(t, int64(changeTime), task.StartTime)

	oldProcessID := task.ProcessID
	newStartTime := int64(92348752934856)
	changes = map[string]interface{}{
		"StartTime": newStartTime,
	}
	b = task.Update(changes, uint64(sys.CurrentMonotonicRaw()), procFS)
	assert.True(t, b)
	assert.Equal(t, newStartTime, task.StartTime)
	assert.NotEqual(t, oldProcessID, task.ProcessID)

	changes = map[string]interface{}{
		"StartTime": int64(0),
	}
	b = task.Update(changes, uint64(sys.CurrentMonotonicRaw()), procFS)
	assert.True(t, b)
	assert.Zero(t, task.StartTime)
	assert.Zero(t, task.ProcessID)

	// Setting ContainerID should nil task.ContainerInfo
	task.ContainerInfo = &ContainerInfo{}
	changes = map[string]interface{}{
		"ContainerID": "dummy container id that doesn't matter",
	}
	b = task.Update(changes, uint64(sys.CurrentMonotonicRaw()), procFS)
	assert.True(t, b)
	assert.Equal(t, changes["ContainerID"], task.ContainerID)
	assert.Nil(t, task.ContainerInfo)

	// Since map enumeration order is not guaranteed, we can't test the
	// case for ContainerInfo set before changing ContainerID.
}

const testCacheSize = uint(1024)

func testTaskCacheImplementation(t *testing.T, cache taskCache) {
	tasks := make([]*Task, testCacheSize)
	for i := 0; i < int(testCacheSize); i++ {
		tasks[i] = cache.LookupTask(i + 1)
	}
	for i := 0; i < int(testCacheSize); i++ {
		task := cache.LookupTask(i + 1)
		assert.Exactly(t, tasks[i], task)
		task.ExitTime = sys.CurrentMonotonicRaw() - taskReuseThreshold
	}
	for i := 0; i < int(testCacheSize); i++ {
		task := cache.LookupTask(i + 1)
		assert.NotEqual(t, tasks[i], task)
	}
}

func TestArrayTaskCache(t *testing.T) {
	cache := newArrayTaskCache(testCacheSize)
	testTaskCacheImplementation(t, cache)
}

func TestMapTaskCache(t *testing.T) {
	cache := newMapTaskCache(testCacheSize)
	testTaskCacheImplementation(t, cache)
}

func TestLookupTaskContainerInfo(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	parentTask := sensor.ProcessCache.LookupTask(2835)
	require.NotNil(t, parentTask)
	changes := map[string]interface{}{
		"TGID": parentTask.PID,
	}
	parentTask.Update(changes, uint64(sys.CurrentMonotonicRaw()), sensor.ProcFS)

	task := sensor.ProcessCache.LookupTask(2836)
	require.NotNil(t, task)
	task.parent = parentTask
	changes = map[string]interface{}{
		"TGID": parentTask.TGID,
	}
	task.Update(changes, uint64(sys.CurrentMonotonicRaw()), sensor.ProcFS)

	info := sensor.ProcessCache.LookupTaskContainerInfo(task)
	assert.Nil(t, info)

	containerID := "98ca8f25f1641d4b4f3c2cb360eaf8763abbf000541679f44c5c782eadbbfdcf"
	ci := sensor.ContainerCache.LookupContainer(containerID, true)
	require.NotNil(t, ci)

	changes = map[string]interface{}{
		"ContainerID": containerID,
	}
	parentTask.Update(changes, uint64(sys.CurrentMonotonicRaw()), sensor.ProcFS)

	info = sensor.ProcessCache.LookupTaskContainerInfo(parentTask)
	assert.Equal(t, ci, info)

	info = sensor.ProcessCache.LookupTaskContainerInfo(task)
	assert.Equal(t, ci, info)
}

func TestProcessInfoCache(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	cache := NewProcessInfoCache(sensor)
	require.NotNil(t, cache)

	// Test enqueueing of pending actions
	var executedDeferredAction bool
	cache.maybeDeferAction(func() {
		executedDeferredAction = true
	})
	cache.Start()
	assert.True(t, executedDeferredAction)
}

func TestProcessDecoders(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	data := perf.TraceEventSampleData{
		"filename":          "/bin/bash",
		"exec_command_line": []string{"bash", "-l"},

		"code":             int32(234987),
		"exit_status":      uint32(495678),
		"exit_signal":      uint32(11),
		"exit_core_dumped": true,

		"fork_child_pid": int32(9485),
		"fork_child_id":  "some string that is a child process id",

		"cwd": "/var/run/capsule8",
	}

	type testCase struct {
		decoder      perf.TraceEventDecoderFn
		expectedType interface{}
		fieldChecks  map[string]string
	}
	testCases := []testCase{
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessExecEvent,
			expectedType: ProcessExecTelemetryEvent{},
			fieldChecks: map[string]string{
				"filename":          "Filename",
				"exec_command_line": "CommandLine",
			},
		},
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessExitEvent,
			expectedType: ProcessExitTelemetryEvent{},
			fieldChecks: map[string]string{
				"code":             "ExitCode",
				"exit_status":      "ExitStatus",
				"exit_signal":      "ExitSignal",
				"exit_core_dumped": "ExitCoreDumped",
			},
		},
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessForkEvent,
			expectedType: ProcessForkTelemetryEvent{},
			fieldChecks: map[string]string{
				"fork_child_pid": "ChildPID",
				"fork_child_id":  "ChildProcessID",
			},
		},
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessUpdateEvent,
			expectedType: ProcessUpdateTelemetryEvent{},
			fieldChecks: map[string]string{
				"cwd": "CWD",
			},
		},
	}

	for _, tc := range testCases {
		data["common_pid"] = int32(sensorPID)
		i, err := tc.decoder(sample, data)
		assert.Nil(t, i)
		assert.NoError(t, err)

		delete(data, "common_pid")
		i, err = tc.decoder(sample, data)
		require.NotNil(t, i)
		require.NoError(t, err)

		e, ok := i.(TelemetryEvent)
		require.True(t, ok)
		require.IsType(t, tc.expectedType, i)

		ok = testCommonTelemetryEventData(t, sensor, e)
		require.True(t, ok)

		value := reflect.ValueOf(i)
		for k, v := range tc.fieldChecks {
			assert.Equal(t, data[k], value.FieldByName(v).Interface())
		}
	}
}

func TestHandleSysClone(t *testing.T) {
	sample := &perf.SampleRecord{
		Time: 19234876,
		Pid:  234,
		Tid:  234678,
		CPU:  3,
	}
	sampleid := sampleIDFromSample(sample)
	assert.Equal(t, sample.Time, sampleid.Time)
	assert.Equal(t, sample.Pid, sampleid.PID)
	assert.Equal(t, sample.Tid, sampleid.TID)
	assert.Equal(t, sample.CPU, sampleid.CPU)

	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	var (
		forkEvent *ProcessForkTelemetryEvent
		lock      sync.Mutex
	)

	ctx, _ := context.WithCancel(context.Background())
	s := sensor.NewSubscription()
	s.RegisterProcessForkEventFilter(nil)
	status, err := s.Run(ctx, func(event TelemetryEvent) {
		if e, ok := event.(ProcessForkTelemetryEvent); ok {
			lock.Lock()
			forkEvent = &e
			lock.Unlock()
		}
	})
	assert.Len(t, status, 0)
	require.NoError(t, err)

	cache := sensor.ProcessCache
	parentTask := cache.LookupTask(88888)
	changes := map[string]interface{}{
		"TGID":      parentTask.PID,
		"Command":   "/bin/bash",
		"StartTime": int64(sys.CurrentMonotonicRaw()),
		"CWD":       sensor.runtimeDir,
		"Creds":     &Cred{500, 500, 500, 500, 500, 500, 500, 500},
	}
	parentTask.Update(changes, uint64(sys.CurrentMonotonicRaw()), sensor.ProcFS)
	parentLeader := parentTask.Leader()

	childTask := cache.LookupTask(88889)
	cloneFlags := uint64(CLONE_THREAD)
	childComm := "bash"
	sample = &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  uint32(parentTask.PID),
		Tid:  uint32(parentTask.PID),
		CPU:  1,
	}
	cache.handleSysClone(parentTask, parentLeader, childTask,
		cloneFlags, childComm, sample)

	time.Sleep(50 * time.Millisecond)
	lock.Lock()
	if assert.NotNil(t, forkEvent) {
		// Make sure the fork event contains the right information
		assert.Equal(t, int32(childTask.PID), forkEvent.ChildPID)
		assert.Equal(t, childTask.ProcessID, forkEvent.ChildProcessID)
		forkEvent = nil
	}
	lock.Unlock()
	// Make sure childTask is filled in with the right information
	assert.Equal(t, parentTask.TGID, childTask.TGID)
	assert.Equal(t, childComm, childTask.Command)
	assert.Equal(t, parentTask.Creds, childTask.Creds)
	assert.Equal(t, parentLeader, childTask.parent)

	// Make the child thread fork a new process
	aNewTask := cache.LookupTask(90000)
	cloneFlags = uint64(0)
	sample = &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  uint32(childTask.PID),
		Tid:  uint32(childTask.PID),
		CPU:  1,
	}
	cache.handleSysClone(childTask, parentLeader, aNewTask, cloneFlags,
		childComm, sample)

	time.Sleep(50 * time.Millisecond)
	lock.Lock()
	if assert.NotNil(t, forkEvent) {
		// Make sure the fork event contains the right information
		assert.Equal(t, int32(aNewTask.PID), forkEvent.ChildPID)
		assert.Equal(t, aNewTask.ProcessID, forkEvent.ChildProcessID)
		forkEvent = nil
	}
	lock.Unlock()
	// Make sure aNewTask is filled in with the right information
	assert.Equal(t, aNewTask.PID, aNewTask.TGID)
	assert.Equal(t, childComm, aNewTask.Command)
	assert.Equal(t, childTask.Creds, aNewTask.Creds)
	assert.Equal(t, parentLeader, aNewTask.parent)
}

func TestDecodeNewTask(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	var (
		forkEvent *ProcessForkTelemetryEvent
		lock      sync.Mutex
	)

	ctx, _ := context.WithCancel(context.Background())
	s := sensor.NewSubscription()
	s.RegisterProcessForkEventFilter(nil)
	status, err := s.Run(ctx, func(event TelemetryEvent) {
		if e, ok := event.(ProcessForkTelemetryEvent); ok {
			lock.Lock()
			forkEvent = &e
			lock.Unlock()
		}
	})
	assert.Len(t, status, 0)
	require.NoError(t, err)

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  405,
		Tid:  405,
	}
	data := perf.TraceEventSampleData{
		"common_pid":  int32(405),
		"pid":         int32(410),
		"clone_flags": uint64(0),
		"comm":        commAsBytes,
	}
	i, err := sensor.ProcessCache.decodeNewTask(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	lock.Lock()
	if assert.NotNil(t, forkEvent) {
		assert.Equal(t, data["pid"], forkEvent.ChildPID)
		forkEvent = nil
	}
	lock.Unlock()
}

func TestDecodeDoExit(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	var (
		exitEvent *ProcessExitTelemetryEvent
		lock      sync.Mutex
	)

	ctx, _ := context.WithCancel(context.Background())
	s := sensor.NewSubscription()
	s.RegisterProcessExitEventFilter(nil)
	status, err := s.Run(ctx, func(event TelemetryEvent) {
		if e, ok := event.(ProcessExitTelemetryEvent); ok {
			lock.Lock()
			exitEvent = &e
			lock.Unlock()
		}
	})
	assert.Len(t, status, 0)
	require.NoError(t, err)

	type testCase struct {
		exitCode       int32
		exitStatus     uint32
		exitSignal     uint32
		exitCoreDumped bool
	}
	testCases := []testCase{
		testCase{int32(unix.SIGSEGV) | 0x80, 0, uint32(unix.SIGSEGV), true},
		testCase{0xf00, 0xf, 0, false},
	}

	for _, tc := range testCases {
		exitEvent = nil

		task := sensor.ProcessCache.LookupTask(410)
		task.TGID = task.PID

		sample := &perf.SampleRecord{
			Time: uint64(sys.CurrentMonotonicRaw()),
			Pid:  410,
			Tid:  410,
		}
		data := perf.TraceEventSampleData{
			"common_pid": int32(410),
			"code":       int64(tc.exitCode),
		}
		i, err := sensor.ProcessCache.decodeDoExit(sample, data)
		assert.Nil(t, i)
		assert.NoError(t, err)

		time.Sleep(50 * time.Millisecond)
		lock.Lock()
		if assert.NotNil(t, exitEvent) {
			assert.Equal(t, tc.exitCode, exitEvent.ExitCode)
			assert.Equal(t, tc.exitStatus, exitEvent.ExitStatus)
			assert.Equal(t, tc.exitSignal, exitEvent.ExitSignal)
			assert.Equal(t, tc.exitCoreDumped, exitEvent.ExitCoreDumped)
		}
		lock.Unlock()
	}
}

func TestDecodeCommitCreds(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	expected := &Cred{1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888}

	task := sensor.ProcessCache.LookupTask(410)
	task.TGID = task.PID

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  410,
		Tid:  410,
	}
	data := perf.TraceEventSampleData{
		"common_pid": int32(410),
		"uid":        expected.UID,
		"gid":        expected.GID,
		"euid":       expected.EUID,
		"egid":       expected.EGID,
		"suid":       expected.SUID,
		"sgid":       expected.SGID,
		"fsuid":      expected.FSUID,
		"fsgid":      expected.FSGID,
	}
	i, err := sensor.ProcessCache.decodeCommitCreds(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	assert.Equal(t, expected, task.Creds)
}

func TestDecodeDoSetFsPwd(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	task := sensor.ProcessCache.LookupTask(sensorPID)
	expected := task.CWD
	task.CWD = ""

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  uint32(sensorPID),
		Tid:  uint32(sensorPID),
	}
	data := perf.TraceEventSampleData{
		"common_pid": int32(sensorPID),
	}
	i, err := sensor.ProcessCache.decodeDoSetFsPwd(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	assert.Equal(t, expected, task.CWD)
}

func TestDecodeExecve(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	var (
		execEvent *ProcessExecTelemetryEvent
		lock      sync.Mutex
	)

	ctx, _ := context.WithCancel(context.Background())
	s := sensor.NewSubscription()
	s.RegisterProcessExecEventFilter(nil)
	status, err := s.Run(ctx, func(event TelemetryEvent) {
		if e, ok := event.(ProcessExecTelemetryEvent); ok {
			lock.Lock()
			execEvent = &e
			lock.Unlock()
		}
	})
	assert.Len(t, status, 0)
	require.NoError(t, err)

	task := sensor.ProcessCache.LookupTask(410)
	task.TGID = task.PID

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  410,
		Tid:  410,
	}
	data := perf.TraceEventSampleData{
		"common_pid": int32(410),
		"filename":   "/bin/ls",
		"argv0":      "ls",
		"argv1":      "-F",
		"argv2":      "/etc",
		"argv3":      "",
		"argv4":      "",
		"argv5":      "",
	}
	i, err := sensor.ProcessCache.decodeExecve(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	lock.Lock()
	if assert.NotNil(t, execEvent) {
		assert.Equal(t, data["filename"], execEvent.Filename)

		commandLine := []string{"ls", "-F", "/etc"}
		assert.Equal(t, commandLine, execEvent.CommandLine)

		task = sensor.ProcessCache.LookupTask(410)
		assert.Equal(t, commandLine, task.CommandLine)
	}
	lock.Unlock()
}

func TestDecodeDoFork(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	var (
		forkEvent *ProcessForkTelemetryEvent
		lock      sync.Mutex
	)

	ctx, _ := context.WithCancel(context.Background())
	s := sensor.NewSubscription()
	s.RegisterProcessForkEventFilter(nil)
	status, err := s.Run(ctx, func(event TelemetryEvent) {
		if e, ok := event.(ProcessForkTelemetryEvent); ok {
			lock.Lock()
			forkEvent = &e
			lock.Unlock()
		}
	})
	assert.Len(t, status, 0)
	require.NoError(t, err)

	task := sensor.ProcessCache.LookupTask(410)
	task.TGID = task.PID

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  410,
		Tid:  410,
	}
	data := perf.TraceEventSampleData{
		"common_pid":  int32(410),
		"clone_flags": uint64(29384576245),
	}

	for x := 0; x < 2; x++ {
		var i interface{}
		i, err = sensor.ProcessCache.decodeDoFork(sample, data)
		assert.Nil(t, i)
		assert.NoError(t, err)

		task = sensor.ProcessCache.LookupTask(410)
		if assert.NotNil(t, task.pendingClone) {
			assert.Equal(t, sample.Time, task.pendingClone.timestamp)
			assert.Equal(t, data["clone_flags"], task.pendingClone.cloneFlags)
		}
	}

	task = sensor.ProcessCache.LookupTask(410)
	task.pendingClone.cloneFlags = 0
	task.pendingClone.childPid = 4120

	i, err := sensor.ProcessCache.decodeDoFork(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	task = sensor.ProcessCache.LookupTask(410)
	assert.Nil(t, task.pendingClone)

	lock.Lock()
	if assert.NotNil(t, forkEvent) {
		assert.Equal(t, int32(4120), forkEvent.ChildPID)
		assert.NotZero(t, forkEvent.ChildProcessID)
	}
	lock.Unlock()
}

func TestDecodeSchedProcessFork(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	var (
		forkEvent *ProcessForkTelemetryEvent
		lock      sync.Mutex
	)

	ctx, _ := context.WithCancel(context.Background())
	s := sensor.NewSubscription()
	s.RegisterProcessForkEventFilter(nil)
	status, err := s.Run(ctx, func(event TelemetryEvent) {
		if e, ok := event.(ProcessForkTelemetryEvent); ok {
			lock.Lock()
			forkEvent = &e
			lock.Unlock()
		}
	})
	assert.Len(t, status, 0)
	require.NoError(t, err)

	task := sensor.ProcessCache.LookupTask(410)
	task.TGID = task.PID

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
		Pid:  410,
		Tid:  410,
	}
	data := perf.TraceEventSampleData{
		"common_pid": int32(410),
		"parent_pid": int32(410),
		"child_pid":  int32(4120),
		"child_comm": commAsBytes,
	}

	i, err := sensor.ProcessCache.decodeSchedProcessFork(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	task = sensor.ProcessCache.LookupTask(410)
	if assert.NotNil(t, task.pendingClone) {
		assert.Equal(t, sample.Time, task.pendingClone.timestamp)
		assert.Equal(t, int(data["child_pid"].(int32)), task.pendingClone.childPid)
	}

	i, err = sensor.ProcessCache.decodeSchedProcessFork(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	task = sensor.ProcessCache.LookupTask(410)
	assert.Nil(t, task.pendingClone)

	lock.Lock()
	if assert.NotNil(t, forkEvent) {
		assert.Equal(t, int32(4120), forkEvent.ChildPID)
		assert.NotZero(t, forkEvent.ChildProcessID)
	}
	lock.Unlock()
}

func TestDecodeCgroupProcsWrite(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	parentTask := sensor.ProcessCache.LookupTask(410)
	parentTask.TGID = parentTask.PID

	childTask := sensor.ProcessCache.LookupTask(4120)
	childTask.TGID = parentTask.PID
	childTask.parent = parentTask

	invalidContainerID := "cgroup name that isn't a container name"
	validContainerID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	sample := &perf.SampleRecord{Time: uint64(sys.CurrentMonotonicRaw())}
	data := perf.TraceEventSampleData{
		"container_id": invalidContainerID,
	}
	i, err := sensor.ProcessCache.decodeCgroupProcsWrite(sample, data)
	assert.Nil(t, i)
	assert.NoError(t, err)

	type testCase struct {
		data perf.TraceEventSampleData
		pid  int
	}
	testCases := []testCase{
		testCase{
			data: perf.TraceEventSampleData{
				"buf":         "4120",
				"threadgroup": int32(1),
			},
			pid: 410,
		},
		testCase{
			data: perf.TraceEventSampleData{
				"buf":         "4120",
				"threadgroup": int32(0),
			},
			pid: 4120,
		},
		testCase{
			data: perf.TraceEventSampleData{
				"tgid": uint64(4120),
			},
			pid: 410,
		},
		testCase{
			data: perf.TraceEventSampleData{
				"pid": uint64(4120),
			},
			pid: 4120,
		},
	}
	for _, tc := range testCases {
		task, leader := sensor.ProcessCache.LookupTaskAndLeader(4120)
		task.ContainerID = ""
		leader.ContainerID = ""

		tc.data["container_id"] = validContainerID

		i, err = sensor.ProcessCache.decodeCgroupProcsWrite(sample, tc.data)
		assert.Nil(t, i)
		assert.NoError(t, err)

		task = sensor.ProcessCache.LookupTask(tc.pid)
		assert.Equal(t, validContainerID, task.ContainerID)
	}

}

var commAsBytes = []interface{}{
	int8('w'), uint8('h'), int8('a'), uint8('t'), int8('e'), uint8('v'), int8('e'), uint8('r'),
	int8(0), uint8(0), int8(0), uint8(0), int8(0), uint8(0), int8(0), uint8(0),
}

var commAsBytes2 = []interface{}{
	int8('w'), uint8('h'), int8('a'), uint8('t'), int8('e'), uint8('v'), int8('e'), uint8('r'),
}

func TestCommToString(t *testing.T) {
	s := commToString(commAsBytes)
	assert.Equal(t, "whatever", s)

	s = commToString(commAsBytes2)
	assert.Equal(t, "whatever", s)
}

func TestProcessEventRegistration(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()

	e := expression.Equal(expression.Identifier("foo"), expression.Value("bar"))
	expr, err := expression.NewExpression(e)
	require.NotNil(t, expr)
	require.NoError(t, err)

	funcs := []func(*expression.Expression){
		s.RegisterProcessExecEventFilter,
		s.RegisterProcessExitEventFilter,
		s.RegisterProcessForkEventFilter,
		s.RegisterProcessUpdateEventFilter,
	}
	for i, f := range funcs {
		f(expr)
		assert.Len(t, s.status, i+1)
		assert.Len(t, s.eventSinks, i)

		f(nil)
		assert.Len(t, s.eventSinks, i+1)
	}
}
