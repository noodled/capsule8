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

package proc

// FileSystem is an interface for obtaining system information from the Linux
// proc filesystem.
type FileSystem interface {
	// BootID returns the kernel's boot identifier
	BootID() string

	// MaxPid returns the maximum PID that the kernel will use.
	MaxPID() uint

	// NumCPU returns the number of CPUs on the system. This differs from
	// runtime.NumCPU in that runtime.NumCPU returns the number of logical
	// CPUs available to the calling process.
	NumCPU() int

	// Mounts returns the list of currently mounted filesystems.
	Mounts() []Mount

	// HostFileSystem returns a FileSystem representing the underlying
	// host's procfs from the perspective of the active proc.FileSystem.
	// If the calling process is running in the host pid namespace, the
	// receiver may return itself. If the calling process is running in a
	// container and no host proc filesystem is mounted in, the return will
	// be nil.
	HostFileSystem() FileSystem

	// PerfEventDir returns the perf_event cgroup mountpoint to use to
	// monitor specific cgroups. Return the empty string if no perf_event
	// cgroup filesystem is mounted.
	PerfEventDir() string

	// TracingDir returns the tracefs mountpoint to use to control the
	// Linux kernel trace event subsystem. Returns the empty string if no
	// tracefs filesystem is mounted.
	TracingDir() string

	// KernelTextSymbolNames returns a mapping of kernel symbols in the
	// text segment. For each symbol in the map, the key is the source name
	// for the symbol, and the value is the actual linker name that should
	// be used for things like kprobes.
	KernelTextSymbolNames() (map[string]string, error)

	// ProcessContainerID returns the container ID running the specified
	// process. If the process is not running inside of a container, the
	// return will be the empty string.
	ProcessContainerID(pid int) (string, error)

	// ProcessCommandLine returns the full command-line arguments of the
	// specified process.
	ProcessCommandLine(pid int) ([]string, error)

	// TaskControlGroups returns the cgroup membership of the specified task.
	TaskControlGroups(tgid, pid int) ([]ControlGroup, error)

	// TaskCWD returns the current working dirtectory for the specified
	// task.
	TaskCWD(tgid, pid int) (string, error)

	// TaskStartTime returns the time at which the specified task started.
	TaskStartTime(tgid, pid int) (int64, error)

	// TaskUniqueID returns a unique task ID for the specified task.
	TaskUniqueID(tgid, pid int, startTime int64) (string, error)

	// WalkTasks calls the specified function for each task present in the
	// proc FileSystem.
	WalkTasks(walkFunc TaskWalkFunc) error

	// ReadTaskStatus reads the status of a task, storing the information
	// into the supplied struct. The supplied struct must be a pointer.
	ReadTaskStatus(tgid, pid int, i interface{}) error
}

// TaskWalkFunc is a function that is called by WalkTasks for each TGID and PID
// encountered during the walk. The return is a boolean indicator of whether
// walk should continue.
type TaskWalkFunc func(tgid, pid int) bool

// Mount holds information about a mount in the process's mount namespace.
type Mount struct {
	MountID        uint
	ParentID       uint
	Major          uint
	Minor          uint
	Root           string
	MountPoint     string
	MountOptions   []string
	OptionalFields map[string]string
	FilesystemType string
	MountSource    string
	SuperOptions   map[string]string
}

// ControlGroup describes the cgroup membership of a process
type ControlGroup struct {
	// Unique hierarchy ID
	ID int

	// Cgroup controllers (subsystems) bound to the hierarchy
	Controllers []string

	// Path is the pathname of the control group to which the process
	// belongs. It is relative to the mountpoint of the hierarchy.
	Path string
}
