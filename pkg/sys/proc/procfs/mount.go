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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/capsule8/capsule8/pkg/sys/proc"

	"github.com/golang/glog"
)

func parseMount(line string) (proc.Mount, error) {
	fields := strings.Fields(line)

	mountID, err := strconv.Atoi(fields[0])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse mountID %q", fields[0])
	}

	parentID, err := strconv.Atoi(fields[1])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse parentID %q", fields[1])
	}

	mm := strings.Split(fields[2], ":")
	major, err := strconv.Atoi(mm[0])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse major %q", mm[0])
	}

	minor, err := strconv.Atoi(mm[1])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse minor %q", mm[1])
	}

	mountOptions := strings.Split(fields[5], ",")

	optionalFieldsMap := make(map[string]string)
	var i int
	for i = 6; fields[i] != "-"; i++ {
		tagValue := strings.Split(fields[i], ":")
		if len(tagValue) == 1 {
			optionalFieldsMap[tagValue[0]] = ""
		} else {
			optionalFieldsMap[tagValue[0]] = strings.Join(tagValue[1:], ":")
		}
	}

	filesystemType := fields[i+1]
	mountSource := fields[i+2]
	superOptions := fields[i+3]

	superOptionsMap := make(map[string]string)
	for _, option := range strings.Split(superOptions, ",") {
		nameValue := strings.Split(option, "=")
		if len(nameValue) == 1 {
			superOptionsMap[nameValue[0]] = ""
		} else {
			superOptionsMap[nameValue[0]] = strings.Join(nameValue[1:], ":")
		}
	}

	return proc.Mount{
		MountID:        uint(mountID),
		ParentID:       uint(parentID),
		Major:          uint(major),
		Minor:          uint(minor),
		Root:           fields[3],
		MountPoint:     fields[4],
		MountOptions:   mountOptions,
		OptionalFields: optionalFieldsMap,
		FilesystemType: filesystemType,
		MountSource:    mountSource,
		SuperOptions:   superOptionsMap,
	}, nil
}

// Mounts returns the list of currently mounted filesystems.
func (fs *FileSystem) Mounts() []proc.Mount {
	var mounts []proc.Mount

	data := string(fs.ReadFileOrPanic("self/mountinfo"))
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		if m, err := parseMount(scanner.Text()); err != nil {
			glog.Fatal(err)
		} else {
			mounts = append(mounts, m)
		}
	}

	return mounts
}

func (fs *FileSystem) findHostFileSystem() *FileSystem {
	for _, mi := range fs.Mounts() {
		if mi.FilesystemType == "proc" && mi.MountPoint != fs.MountPoint {
			fs, err := NewFileSystem(mi.MountPoint)
			if err != nil {
				glog.Warning(err)
				continue
			}

			if cgroups, err := fs.TaskControlGroups(1, 1); err != nil {
				glog.Warningf("Cannot get cgroups for pid 1 on procfs %s: %v",
					mi.MountPoint, err)
			} else {
				for _, cg := range cgroups {
					if cg.Path == "/" {
						return fs
					}
				}
			}
		}
	}

	return nil
}

// HostFileSystem returns a FileSystem representing the underlying host's
// procfs from the perspective of the active proc.FileSystem. If the calling
// process is running in the host pid namespace, the receiver may return
// itself. If the calling process is running in a container and no host proc
// filesystem is mounted in, the return will be nil.
func (fs *FileSystem) HostFileSystem() proc.FileSystem {
	fs.hostProcFSOnce.Do(func() {
		// If this filesystem's init process (pid 1) is in one or more
		// root cgroup paths, it is the host filesystem.
		if cgroups, err := fs.TaskControlGroups(1, 1); err != nil {
			glog.Fatalf("Cannot get cgroups for pid 1: %v", err)
		} else {
			for _, cg := range cgroups {
				if cg.Path == "/" {
					fs.hostProcFS = fs
					return
				}
			}
		}

		// Scan this filesystem's view of mounts to look for a host
		// procfs mount.
		fs.hostProcFS = fs.findHostFileSystem()
	})

	return fs.hostProcFS
}

// PerfEventDir returns the perf_event cgroup mountpoint to use to monitor
// specific cgroups. Return the empty string if no perf_event cgroup filesystem
// is mounted.
func (fs *FileSystem) PerfEventDir() string {
	for _, mi := range fs.Mounts() {
		if mi.FilesystemType == "cgroup" {
			for option := range mi.SuperOptions {
				if option == "perf_event" {
					return mi.MountPoint
				}
			}
		}
	}

	return ""
}

// TracingDir returns the tracefs mountpoint to use to control the Linux kernel
// trace event subsystem. Returns the empty string if no tracefs filesystem is
// mounted.
func (fs *FileSystem) TracingDir() string {
	mounts := fs.Mounts()

	// Look for an existing tracefs
	for _, m := range mounts {
		if m.FilesystemType == "tracefs" {
			glog.V(1).Infof("Found tracefs at %s", m.MountPoint)
			return m.MountPoint
		}
	}

	// If no mounted tracefs has been found, look for it as a
	// subdirectory of the older debugfs
	for _, m := range mounts {
		if m.FilesystemType == "debugfs" {
			d := filepath.Join(m.MountPoint, "tracing")
			s, err := os.Stat(filepath.Join(d, "events"))
			if err == nil && s.IsDir() {
				glog.V(1).Infof("Found debugfs w/ tracing at %s", d)
				return d
			}
		}
	}

	return ""
}
