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
	"testing"
)

func TestNewFileSystem(t *testing.T) {
	fs1, err := NewFileSystem("")
	ok(t, err)
	fs2, err := NewFileSystem("")
	ok(t, err)
	assert(t, fs1 == fs2,
		"Default procfs is not a singleton")
	assert(t, fs1.MountPoint == "/proc",
		"Default procfs filesystem is mounted at %q", fs1.MountPoint)
}

func TestBootID(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	id := fs.BootID()
	equals(t, "8eb7a4c9-0b6f-4d7f-8f60-98c88eedf67c", id)
}

func TestMaxPID(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	max := fs.MaxPID()
	equals(t, uint(131072), max)
}

func TestNumCPU(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	ncpu := fs.NumCPU()
	equals(t, int(2), ncpu)
}

func TestReadFile(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	expectedBytes := []byte{'1', '3', '1', '0', '7', '2', '\n'}

	actualBytes, err := fs.ReadFile("sys/kernel/pid_max")
	ok(t, err)

	equals(t, expectedBytes, actualBytes)
}
