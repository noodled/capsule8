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

package sensor

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var kprobeFormats = map[string]string{
	"dofork": `name: sensor_^^PID^^_dofork
ID: 1616
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:u64 clone_flags;	offset:16;	size:8;	signed:0;

print fmt: "clone_flags=%d", REC->clone_flags`,
	"_dofork": `name: sensor_^^PID^^__dofork
ID: 1617
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:u64 clone_flags;	offset:16;	size:8;	signed:0;

print fmt: "clone_flags=%d", REC->clone_flags`,
	"doexit": `name: sensor_^^PID^^_doexit
ID: 1618
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:s64 code;	offset:16;	size:8;	signed:1;

print fmt: "(%lx) code=%Ld", REC->__probe_ip, REC->code`,
	"creds": `name: sensor_^^PID^^_creds
ID: 1619
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:u64 usage;	offset:16;	size:8;	signed:0;
	field:u32 uid;	offset:24;	size:4;	signed:0;
	field:u32 gid;	offset:28;	size:4;	signed:0;
	field:u32 suid;	offset:32;	size:4;	signed:0;
	field:u32 sgid;	offset:36;	size:4;	signed:0;
	field:u32 euid;	offset:40;	size:4;	signed:0;
	field:u32 egid;	offset:44;	size:4;	signed:0;
	field:u32 fsuid;	offset:48;	size:4;	signed:0;
	field:u32 fsgid;	offset:52;	size:4;	signed:0;

print fmt: "(%lx) usage=%Lu uid=%u gid=%u suid=%u sgid=%u euid=%u egid=%u fsuid=%u fsgid=%u", REC->__probe_ip, REC->usage, REC->uid, REC->gid, REC->suid, REC->sgid, REC->euid, REC->egid, REC->fsuid, REC->fsgid`,
	"setfspwd": `name: sensor_^^PID^^_setfspwd
ID: 1620
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_func;	offset:8;	size:8;	signed:0;
	field:unsigned long __probe_ret_ip;	offset:16;	size:8;	signed:0;

print fmt: "(%lx <- %lx)", REC->__probe_func, REC->__probe_ret_ip`,
	"execve1": `name: sensor_^^PID^^_execve1
ID: 1621
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] filename;	offset:16;	size:4;	signed:1;
	field:__data_loc char[] argv0;	offset:20;	size:4;	signed:1;
	field:__data_loc char[] argv1;	offset:24;	size:4;	signed:1;
	field:__data_loc char[] argv2;	offset:28;	size:4;	signed:1;
	field:__data_loc char[] argv3;	offset:32;	size:4;	signed:1;
	field:__data_loc char[] argv4;	offset:36;	size:4;	signed:1;
	field:__data_loc char[] argv5;	offset:40;	size:4;	signed:1;

print fmt: "(%lx) filename=\"%s\" argv0=\"%s\" argv1=\"%s\" argv2=\"%s\" argv3=\"%s\" argv4=\"%s\" argv5=\"%s\"", REC->__probe_ip, __get_str(filename), __get_str(argv0), __get_str(argv1), __get_str(argv2), __get_str(argv3), __get_str(argv4), __get_str(argv5)`,
	"execve2": `name: sensor_^^PID^^_execve2
ID: 1622
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] filename;	offset:16;	size:4;	signed:1;
	field:__data_loc char[] argv0;	offset:20;	size:4;	signed:1;
	field:__data_loc char[] argv1;	offset:24;	size:4;	signed:1;
	field:__data_loc char[] argv2;	offset:28;	size:4;	signed:1;
	field:__data_loc char[] argv3;	offset:32;	size:4;	signed:1;
	field:__data_loc char[] argv4;	offset:36;	size:4;	signed:1;
	field:__data_loc char[] argv5;	offset:40;	size:4;	signed:1;

print fmt: "(%lx) filename=\"%s\" argv0=\"%s\" argv1=\"%s\" argv2=\"%s\" argv3=\"%s\" argv4=\"%s\" argv5=\"%s\"", REC->__probe_ip, __get_str(filename), __get_str(argv0), __get_str(argv1), __get_str(argv2), __get_str(argv3), __get_str(argv4), __get_str(argv5)`,
	"execveat1": `name: sensor_^^PID^^_execveat1
ID: 1623
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] filename;	offset:16;	size:4;	signed:1;
	field:__data_loc char[] argv0;	offset:20;	size:4;	signed:1;
	field:__data_loc char[] argv1;	offset:24;	size:4;	signed:1;
	field:__data_loc char[] argv2;	offset:28;	size:4;	signed:1;
	field:__data_loc char[] argv3;	offset:32;	size:4;	signed:1;
	field:__data_loc char[] argv4;	offset:36;	size:4;	signed:1;
	field:__data_loc char[] argv5;	offset:40;	size:4;	signed:1;

print fmt: "(%lx) filename=\"%s\" argv0=\"%s\" argv1=\"%s\" argv2=\"%s\" argv3=\"%s\" argv4=\"%s\" argv5=\"%s\"", REC->__probe_ip, __get_str(filename), __get_str(argv0), __get_str(argv1), __get_str(argv2), __get_str(argv3), __get_str(argv4), __get_str(argv5)`,
	"execveat2": `name: sensor_^^PID^^_execveat2
ID: 1624
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] argv0;	offset:16;	size:4;	signed:1;
	field:__data_loc char[] argv1;	offset:20;	size:4;	signed:1;
	field:__data_loc char[] argv2;	offset:24;	size:4;	signed:1;
	field:__data_loc char[] argv3;	offset:28;	size:4;	signed:1;
	field:__data_loc char[] argv4;	offset:32;	size:4;	signed:1;
	field:__data_loc char[] argv5;	offset:36;	size:4;	signed:1;

print fmt: "(%lx) argv0=\"%s\" argv1=\"%s\" argv2=\"%s\" argv3=\"%s\" argv4=\"%s\" argv5=\"%s\"", REC->__probe_ip, __get_str(argv0), __get_str(argv1), __get_str(argv2), __get_str(argv3), __get_str(argv4), __get_str(argv5)`,
	"cgroups1": `name: sensor_^^PID^^_cgroups1
ID: 1625
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] container_id;	offset:16;	size:4;	signed:1;
	field:__data_loc char[] buf;	offset:20;	size:4;	signed:1;
	field:s32 threadgroup;	offset:24;	size:4;	signed:1;

print fmt: "(%lx) container_id=\"%s\" buf=\"%s\" threadgroup=%d", REC->__probe_ip, __get_str(container_id), __get_str(buf), REC->threadgroup`,
	"cgroups2": `name: sensor_^^PID^^_cgroups2
ID: 1625
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] container_id;	offset:16;	size:4;	signed:1;
	field:__data_loc char[] buf;	offset:20;	size:4;	signed:1;
	field:s32 threadgroup;	offset:24;	size:4;	signed:1;

print fmt: "(%lx) container_id=\"%s\" buf=\"%s\" threadgroup=%d", REC->__probe_ip, __get_str(container_id), __get_str(buf), REC->threadgroup`,
	"docker1": `name: sensor_^^PID^^_docker1
ID: 1626
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] newname;	offset:16;	size:4;	signed:1;

print fmt: "(%lx) newname=\"%s\"", REC->__probe_ip, __get_str(newname)`,
	"docker2": `name: sensor_^^PID^^_docker2
ID: 1627
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] pathname;	offset:16;	size:4;	signed:1;

print fmt: "(%lx) pathname=\"%s\"", REC->__probe_ip, __get_str(pathname)`,
}

func writeFile(t *testing.T, filename string, data []byte) {
	err := os.MkdirAll(filepath.Dir(filename), 0777)
	require.NoError(t, err)

	err = ioutil.WriteFile(filename, data, 0666)
	require.NoError(t, err)
}

var nextProbeID uint64 = 8800

func newUnitTestKprobe(t *testing.T, sensor *Sensor, format string) {
	require.True(t, strings.HasPrefix(format, "name: ^^NAME^^"))

	nextProbeName := sensor.Monitor.NextProbeName()
	probeNameParts := strings.Split(nextProbeName, "/")
	nextProbeID++

	name := probeNameParts[1]
	format = strings.Replace(format, "^^NAME^^", name, -1)
	format = strings.Replace(format, "^^ID^^", fmt.Sprintf("%d", nextProbeID), -1)
	filename := filepath.Join(sensor.tracingDir, "events", probeNameParts[0],
		probeNameParts[1], "format")

	writeFile(t, filename, ([]byte)(format))
}

func recursiveCopy(t *testing.T, sourceDir, targetDir string) {
	err := filepath.Walk(sourceDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			sourceFilename := path
			targetFilename := filepath.Join(targetDir, path[len(sourceDir):])
			if info.IsDir() {
				err = os.MkdirAll(targetFilename, 0777)
			} else {
				var data []byte
				data, err = ioutil.ReadFile(sourceFilename)
				if err == nil {
					writeFile(t, targetFilename, data)
				}
			}
			return err
		})
	require.NoError(t, err)
}

func newUnstartedUnitTestSensor(t *testing.T) *Sensor {
	procFS, err := procfs.NewFileSystem("testdata")
	require.NoError(t, err)

	runtimeDir, err := ioutil.TempDir("", "capsule8_")
	require.NoError(t, err)

	defer func() {
		if err != nil {
			os.RemoveAll(runtimeDir)
		}
	}()

	dockerDir := filepath.Join(runtimeDir, "docker")
	err = os.MkdirAll(dockerDir, 0777)
	require.NoError(t, err)

	tracingDir := filepath.Join(runtimeDir, "tracing")
	err = os.MkdirAll(tracingDir, 0777)
	require.NoError(t, err)

	kprobeEvents := filepath.Join(tracingDir, "kprobe_events")
	writeFile(t, kprobeEvents, []byte{})

	sourceDir := filepath.Join("testdata", "events")
	targetDir := filepath.Join(tracingDir, "events")
	recursiveCopy(t, sourceDir, targetDir)

	sourceDir = filepath.Join("testdata", "docker")
	recursiveCopy(t, sourceDir, dockerDir)

	pidString := fmt.Sprintf("%d", os.Getpid())
	for k, format := range kprobeFormats {
		format = strings.Replace(format, "^^PID^^", pidString, -1)
		filename := filepath.Join(tracingDir, "events", "capsule8",
			fmt.Sprintf("sensor_%d_%s", os.Getpid(), k), "format")
		writeFile(t, filename, ([]byte)(filename))
	}

	sensor, err := NewSensor(
		WithRuntimeDir(runtimeDir),
		WithDockerContainerDir(dockerDir),
		WithProcFileSystem(procFS),
		WithEventSourceController(perf.NewStubEventSourceController()),
		WithTracingDir(tracingDir),
		WithCleanupFunc(func() { os.RemoveAll(runtimeDir) }))
	require.NoError(t, err)

	// Set sensorPID to 76989 so that PID 76989 is considered to be the
	// sensor. This is what is in the testdata.
	sensorPID = 76989

	return sensor
}

func newUnitTestSensor(t *testing.T) *Sensor {
	sensor := newUnstartedUnitTestSensor(t)

	err := sensor.Start()
	require.NoError(t, err)

	return sensor
}

func TestNewSensorOptions(t *testing.T) {
	procFS, err := procfs.NewFileSystem("testdata")
	require.NoError(t, err)

	expOptions := newSensorOptions{
		runtimeDir:            "runtimeDir",
		perfEventDir:          "perfEventDir",
		tracingDir:            "tracingDir",
		dockerContainerDir:    "dockerContainerDir",
		ociContainerDir:       "ociContainerDir",
		procFS:                procFS,
		eventSourceController: perf.NewStubEventSourceController(),
		cgroupNames:           []string{"abc", "def", "ghi"},
	}

	options := []NewSensorOption{
		WithRuntimeDir(expOptions.runtimeDir),
		WithDockerContainerDir(expOptions.dockerContainerDir),
		WithOciContainerDir(expOptions.ociContainerDir),
		WithProcFileSystem(expOptions.procFS),
		WithEventSourceController(expOptions.eventSourceController),
		WithPerfEventDir(expOptions.perfEventDir),
		WithTracingDir(expOptions.tracingDir),
	}
	for _, n := range expOptions.cgroupNames {
		options = append(options, WithCgroupName(n))
	}

	actOptions := newSensorOptions{}
	for _, option := range options {
		option(&actOptions)
	}

	assert.Equal(t, expOptions, actOptions)
}

func TestBuildMonitorGroups(t *testing.T) {
	sensor := Sensor{perfEventDir: "perfEventDir"}
	cgroupList, pidList, err := sensor.buildMonitorGroups()
	assert.Zero(t, cgroupList)
	assert.Equal(t, []int{-1}, pidList)
	assert.NoError(t, err)

	sensor.cgroupNames = []string{"/"}
	cgroupList, pidList, err = sensor.buildMonitorGroups()
	assert.Zero(t, cgroupList)
	assert.Equal(t, []int{-1}, pidList)
	assert.NoError(t, err)

	sensor.cgroupNames = []string{"foo", "foo", "bar"}
	cgroupList, pidList, err = sensor.buildMonitorGroups()
	assert.Equal(t, []string{"foo", "bar"}, cgroupList)
	assert.Zero(t, pidList)
	assert.NoError(t, err)
}

func TestActualKernelSymbol(t *testing.T) {
	s := Sensor{}
	s.kallsyms = map[string]string{
		"create_dev":           "create_dev.constprop.6",
		"__x64_sys_setuid":     "__x64_sys_setuid",
		"__cgroup_procs_write": "__cgroup_procs_write",
	}

	tests := map[string]string{
		"__cgroup_procs_write": "__cgroup_procs_write",
		"create_dev":           "create_dev.constprop.6",
		"sys_setuid":           "__x64_sys_setuid",
	}
	for sym, exp := range tests {
		got, err := s.ActualKernelSymbol(sym)
		if assert.NoError(t, err) {
			assert.Equal(t, exp, got)
		}
	}
}

func TestRewriteSyscallFetchargs(t *testing.T) {
	args := map[string]string{
		"a=+0(%di):string": "a=+0(+0x70(%di)):string",
		"b=%si:s32":        "b=+0x68(%di):s32",
		"c=%dx:u64":        "c=+0x60(%di):u64",
		"d=%cx:u16":        "d=+0x38(%di):u16",
		"e=%r8:s8":         "e=+0x48(%di):s8",
		"f=+0(%r9):string": "f=+0(+0x40(%di)):string",
		"g=%ax:s32":        "g=+0x50(%di):s32",
	}

	var inputArray, expArray []string
	for k, v := range args {
		inputArray = append(inputArray, k)
		expArray = append(expArray, v)
	}
	input := strings.Join(inputArray, " ")
	exp := strings.Join(expArray, " ")
	got := rewriteSyscallFetchargs(input)
	assert.Equal(t, exp, got)
}

func TestNewSubscription(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	assert.NotNil(t, s)
	assert.Equal(t, sensor, s.sensor)
	assert.Equal(t, uint64(1), s.subscriptionID)
}

func TestPushPopSamples(t *testing.T) {
	sensor := newUnstartedUnitTestSensor(t)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		sensor.dispatchMutex.Lock()
		for {
			sensor.dispatchCond.Wait()
			if sensor.dispatchQueueHead != nil {
				break
			}
		}
		sensor.dispatchMutex.Unlock()

		wg.Done()
	}()

	time.Sleep(50 * time.Millisecond)
	sensor.dispatchSamples([]perf.EventMonitorSample{perf.EventMonitorSample{}})
	wg.Wait()
	assert.NotNil(t, sensor.dispatchQueueHead)
	assert.NotNil(t, sensor.dispatchQueueTail)
	assert.Equal(t, sensor.dispatchQueueHead, sensor.dispatchQueueTail)

	sensor.dispatchSamples([]perf.EventMonitorSample{perf.EventMonitorSample{}})
	assert.NotNil(t, sensor.dispatchQueueHead)
	assert.NotNil(t, sensor.dispatchQueueTail)
	assert.NotEqual(t, sensor.dispatchQueueHead, sensor.dispatchQueueTail)

	samples := sensor.popSamples()
	assert.Len(t, samples, 1)
	assert.NotNil(t, sensor.dispatchQueueHead)
	assert.NotNil(t, sensor.dispatchQueueTail)
	assert.Equal(t, sensor.dispatchQueueHead, sensor.dispatchQueueTail)
	assert.NotNil(t, sensor.dispatchFreelist)

	samples = sensor.popSamples()
	assert.Len(t, samples, 1)
	assert.Nil(t, sensor.dispatchQueueHead)
	assert.Nil(t, sensor.dispatchQueueTail)
	assert.NotNil(t, sensor.dispatchFreelist)
}

func TestDispatchQueuedSamples(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	eventID := sensor.Monitor.RegisterExternalEvent("dispatch test",
		func(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
			// This should not get called
			t.Fatal("Unexpected call to external event decoder")
			return nil, nil
		})

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	expr, err := expression.NewExpression(
		expression.Equal(
			expression.Identifier("filename"),
			expression.Value("/etc/passwd")))
	require.NoError(t, err)

	eventSink, err := s.addEventSink(eventID, expr, FileOpenEventTypes)
	require.NoError(t, err)
	require.NotNil(t, eventSink)

	// Check to make sure we don't get any samples dispatched. This is more
	// for coverage than anything -- there's not a good way to test this.
	ctx, _ := context.WithCancel(context.Background())
	s.Run(ctx, func(event TelemetryEvent) {
		t.Fatalf("Unexpected receipt of telemetry event %#v\n", event)
	})
	badSamples := []perf.EventMonitorSample{
		perf.EventMonitorSample{
			EventID: eventID,
			Err:     errors.New("this is an error"),
		},
		perf.EventMonitorSample{
			EventID:       eventID,
			DecodedSample: "this is not TelemetryEvent",
		},
		perf.EventMonitorSample{
			EventID:       eventID,
			DecodedSample: TelemetryEvent(nil),
		},
		perf.EventMonitorSample{
			EventID:       2394857,
			DecodedSample: FileOpenTelemetryEvent{},
		},
	}
	sensor.dispatchQueuedSamples(badSamples)

	samples := []perf.EventMonitorSample{
		perf.EventMonitorSample{
			EventID:       eventID,
			DecodedSample: FileOpenTelemetryEvent{},
			DecodedData: map[string]interface{}{
				"filename": "foo",
			},
		},
		perf.EventMonitorSample{
			EventID:       eventID,
			DecodedSample: FileOpenTelemetryEvent{},
			DecodedData: map[string]interface{}{
				"filename": 32,
			},
		},
		perf.EventMonitorSample{
			EventID: eventID,
			DecodedSample: FileOpenTelemetryEvent{
				Filename: "/etc/passwd",
			},
			DecodedData: map[string]interface{}{
				"filename": "/etc/passwd",
			},
		},
	}

	var dispatchedSamples []TelemetryEvent
	s.dispatchFn = func(event TelemetryEvent) {
		dispatchedSamples = append(dispatchedSamples, event)
	}
	sensor.dispatchQueuedSamples(samples)
	assert.Len(t, dispatchedSamples, 1)
	assert.Equal(t, samples[2].DecodedSample, dispatchedSamples[0])

	// Attach a container filter to the subscription and ensure that it is
	// applied.
	filter := NewContainerFilter()
	filter.AddContainerID("container id who cares what it is")
	s.SetContainerFilter(filter)

	samples = []perf.EventMonitorSample{
		perf.EventMonitorSample{
			EventID: eventID,
			DecodedSample: FileOpenTelemetryEvent{
				Filename: "/etc/passwd",
			},
			DecodedData: map[string]interface{}{
				"filename": "/etc/passwd",
			},
		},
		perf.EventMonitorSample{
			EventID: eventID,
			DecodedSample: FileOpenTelemetryEvent{
				TelemetryEventData: TelemetryEventData{
					Container: ContainerInfo{
						ID: "container id who cares what it is",
					},
				},
				Filename: "/etc/passwd",
			},
			DecodedData: map[string]interface{}{
				"filename": "/etc/passwd",
			},
		},
	}
	dispatchedSamples = nil
	sensor.dispatchQueuedSamples(samples)
	assert.Len(t, dispatchedSamples, 1)
	assert.Equal(t, samples[1].DecodedSample, dispatchedSamples[0])
}
