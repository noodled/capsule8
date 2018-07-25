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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"

	"github.com/stretchr/testify/require"
)

var kprobeFormats = []string{
	`name: sensor_^^PID^^_1
ID: 1562
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1; signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:s64 code;	offset:16;	size:8;	signed:1;

print fmt: "(%lx) code=%Ld", REC->__probe_ip, REC->code`,

	`name: sensor_^^PID^^_2
ID: 1563
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
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

	`name: sensor_^^PID^^_3
ID: 1564
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_func;	offset:8;	size:8;	signed:0;
	field:unsigned long __probe_ret_ip;	offset:16;	size:8;	signed:0;

print fmt: "(%lx <- %lx)", REC->__probe_func, REC->__probe_ret_ip`,

	`name: sensor_^^PID^^_4
ID: 1565
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
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

	`name: sensor_^^PID^^_5
ID: 1566
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
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

	"", // 6 is not used for some reason?

	`name: sensor_^^PID^^_7
ID: 1567
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

	`name: sensor_^^PID^^_8
ID: 1568
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] newname;	offset:16;	size:4;	signed:1;

print fmt: "(%lx) newname=\"%s\"", REC->__probe_ip, __get_str(newname)`,

	`name: sensor_^^PID^^_9
ID: 1569
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

func newUnitTestSensor(t *testing.T) *Sensor {
	procFS, err := procfs.NewFileSystem("testdata")
	require.NoError(t, err)

	runtimeDir, err := ioutil.TempDir("", "capsule8_")
	require.NoError(t, err)

	defer func() {
		if err != nil {
			os.RemoveAll(runtimeDir)
		}
	}()

	tracingDir := filepath.Join(runtimeDir, "tracing")
	err = os.MkdirAll(tracingDir, 0777)
	require.NoError(t, err)

	kprobeEvents := filepath.Join(tracingDir, "kprobe_events")
	writeFile(t, kprobeEvents, []byte{})

	format := ([]byte)(`name: task_newtask
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

print fmt: "pid=%d comm=%s clone_flags=%lx oom_score_adj=%hd", REC->pid, REC->comm, REC->clone_flags, REC->oom_score_adj`)
	filename := filepath.Join(tracingDir, "events", "task", "task_newtask", "format")
	writeFile(t, filename, format)

	pidString := fmt.Sprintf("%d", os.Getpid())
	for i, format := range kprobeFormats {
		format = strings.Replace(format, "^^PID^^", pidString, -1)
		filename = filepath.Join(tracingDir, "events", "capsule8",
			fmt.Sprintf("sensor_%d_%d", os.Getpid(), i+1), "format")
		writeFile(t, filename, ([]byte)(filename))
	}

	sensor, err := NewSensor(
		WithRuntimeDir(runtimeDir),
		WithProcFileSystem(procFS),
		WithEventSourceController(perf.NewStubEventSourceController()),
		WithTracingDir(tracingDir),
		WithCleanupFunc(func() { os.RemoveAll(runtimeDir) }))
	require.NoError(t, err)

	err = sensor.Start()
	require.NoError(t, err)

	return sensor
}
