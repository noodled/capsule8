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

package procfs

import (
	"github.com/capsule8/capsule8/pkg/sys/proc"
	"testing"
)

func TestProcessContainerID(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	id, err := fs.ProcessContainerID(405)
	ok(t, err)
	equals(t, "", id)

	id, err = fs.ProcessContainerID(111343)
	ok(t, err)
	equals(t, "29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae", id)

	_, err = fs.ProcessContainerID(322)
	assert(t, err != nil, "Expected non-nil error return")
}

func TestProcessCommandLine(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	expectedCommandLine := []string{"/sbin/init", "noprompt"}
	actualCommandLine, err := fs.ProcessCommandLine(1)
	ok(t, err)
	equals(t, expectedCommandLine, actualCommandLine)

	expectedCommandLine = []string{
		"vmware-vmblock-fuse",
		"/run/vmblock-fuse",
		"-o",
		"rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid",
	}
	actualCommandLine, err = fs.ProcessCommandLine(405)
	ok(t, err)
	equals(t, expectedCommandLine, actualCommandLine)

	_, err = fs.ProcessCommandLine(322)
	assert(t, err != nil, "Expected non-nil error return")
}

func TestTaskControlGroups(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	expectedControlGroups := []proc.ControlGroup{
		proc.ControlGroup{
			ID:          11,
			Controllers: []string{"perf_event"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          10,
			Controllers: []string{"freezer"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          9,
			Controllers: []string{"cpuset"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          8,
			Controllers: []string{"devices"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          7,
			Controllers: []string{"hugetlb"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          6,
			Controllers: []string{"pids"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          5,
			Controllers: []string{"cpu", "cpuacct"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          4,
			Controllers: []string{"blkio"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          3,
			Controllers: []string{"net_cls", "net_prio"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          2,
			Controllers: []string{"memory"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
		proc.ControlGroup{
			ID:          1,
			Controllers: []string{"name=systemd"},
			Path:        "/docker/29923fe3b8d282573feac35570414a21546ecc64427b976b178dfa57e04500ae",
		},
	}

	actualControlGroups, err := fs.TaskControlGroups(111343, 111343)
	ok(t, err)
	equals(t, expectedControlGroups, actualControlGroups)

	_, err = fs.TaskControlGroups(322, 223)
	assert(t, err != nil, "Expected non-nil error return")
}

func TestTaskCWD(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	expectedCWD := "/"
	actualCWD, err := fs.TaskCWD(1, 1)
	equals(t, expectedCWD, actualCWD)

	expectedCWD = "/home/capsule8"
	actualCWD, err = fs.TaskCWD(111343, 111343)
	equals(t, expectedCWD, actualCWD)

	_, err = fs.TaskCWD(322, 223)
	assert(t, err != nil, "Expected non-nil error return")
}

func TestStartTime(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	expectedStartTime := int64(1134871)
	actualStartTime, err := fs.TaskStartTime(111343, 111343)
	equals(t, expectedStartTime, actualStartTime)

	_, err = fs.TaskStartTime(322, 223)
	assert(t, err != nil, "Expected non-nil error return")
}

func TestTaskUniqueID(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	startTime, err := fs.TaskStartTime(405, 414)
	ok(t, err)

	expectedUniqueID := "aae249deb87f12637a73bb224b4a7fc6835666860232c8f21ee3cc47f9235df0"
	actualUniqueID, err := fs.TaskUniqueID(405, 414, startTime)
	equals(t, expectedUniqueID, actualUniqueID)
}

func TestWalkTasks(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	knownTasks := map[uint64]bool{
		uint64(1)<<32 | uint64(1):           false,
		uint64(405)<<32 | uint64(405):       false,
		uint64(405)<<32 | uint64(406):       false,
		uint64(405)<<32 | uint64(414):       false,
		uint64(111343)<<32 | uint64(111343): false,
	}

	var count int
	err = fs.WalkTasks(func(tgid, pid int) bool {
		key := (uint64(tgid) << 32) | uint64(pid)
		knownTasks[key] = true
		count++
		return true
	})
	equals(t, len(knownTasks), count)

	for k, v := range knownTasks {
		if !v {
			tgid := int(k >> 32)
			pid := int(k & 0xffffffff)
			t.Errorf("TGID %d PID %d not visited", tgid, pid)
		}
	}
}

func TestReadTaskStatus(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	type status struct {
		Name   string   `Name`
		PID    int32    `Pid`
		TGID   int32    `Tgid`
		FDSize uint64   `FDSize`
		UID    []uint32 `Uid`
		GID    []uint32 `Gid`
	}

	expectedStatus := status{
		Name:   "vmware-vmblock-",
		PID:    406,
		TGID:   405,
		FDSize: 64,
		UID:    []uint32{0, 0, 0, 0},
		GID:    []uint32{0, 0, 0, 0},
	}

	var actualStatus status
	err = fs.ReadTaskStatus(405, 406, &actualStatus)
	ok(t, err)
	equals(t, expectedStatus, actualStatus)

	err = fs.ReadTaskStatus(322, 223, &actualStatus)
	assert(t, err != nil, "Expected non-nil error return")
}
