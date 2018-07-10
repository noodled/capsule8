// Code generated automatically. DO NOT EDIT.
// It isn't really, but the above line causes golint to not check this file.
// This file contains Linux kernel constants that do not conform to Go's
// usual naming conventions. It may at some point in the future become
// automatically generated.

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

package perf

//
// We support PERF_ATTR_SIZE_VER0, which is the first published version
//
const sizeofPerfEventAttrVer0 = 64
const sizeofPerfEventAttrVer1 = 72  // Linux 2.6.33
const sizeofPerfEventAttrVer2 = 80  // Linux 3.4
const sizeofPerfEventAttrVer3 = 96  // Linux 3.7
const sizeofPerfEventAttrVer4 = 104 // Linux 3.19
const sizeofPerfEventAttrVer5 = 112 // Linux 4.1

const sizeofPerfEventAttr = sizeofPerfEventAttrVer0

const (
	PERF_EVENT_IOC_ENABLE       uintptr = 0x2400 + 0
	PERF_EVENT_IOC_DISABLE              = 0x2400 + 1
	PERF_EVENT_IOC_REFRESH              = 0x2400 + 2
	PERF_EVENT_IOC_RESET                = 0x2400 + 3
	PERF_EVENT_IOC_PERIOD               = 0x40080000 | (0x2400 + 4)
	PERF_EVENT_IOC_SET_OUTPUT           = 0x2400 + 5
	PERF_EVENT_IOC_SET_FILTER           = 0x40080000 | (0x2400 + 6)
	PERF_EVENT_IOC_ID                   = 0x80080000 | (0x2400 + 7)
	PERF_EVENT_IOC_SET_BPF              = 0x40040000 | (0x2400 + 8)
	PERF_EVENT_IOC_PAUSE_OUTPUT         = 0x40040000 | (0x2400 + 9)
)

const (
	PERF_EVENT_IOC_FLAG_GROUP uintptr = 1 << iota
)

const (
	PERF_FLAG_FD_NO_GROUP uintptr = 1 << iota
	PERF_FLAG_FD_OUTPUT
	PERF_FLAG_PID_CGROUP
	PERF_FLAG_FD_CLOEXEC
)

const (
	PERF_FORMAT_TOTAL_TIME_ENABLED uint64 = 1 << iota
	PERF_FORMAT_TOTAL_TIME_RUNNING
	PERF_FORMAT_ID
	PERF_FORMAT_GROUP
)

const (
	PERF_RECORD_MISC_COMM_EXEC uint16 = (1 << 13)
)

const (
	PERF_TYPE_HARDWARE uint32 = iota
	PERF_TYPE_SOFTWARE
	PERF_TYPE_TRACEPOINT
	PERF_TYPE_HW_CACHE
	PERF_TYPE_RAW
	PERF_TYPE_BREAKPOINT
	PERF_TYPE_MAX
)

const (
	PERF_COUNT_HW_CPU_CYCLES uint64 = iota
	PERF_COUNT_HW_INSTRUCTIONS
	PERF_COUNT_HW_CACHE_REFERENCES
	PERF_COUNT_HW_CACHE_MISSES
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS
	PERF_COUNT_HW_BRANCH_MISSES
	PERF_COUNT_HW_BUS_CYCLES
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND
	PERF_COUNT_HW_REF_CPU_CYCLES
	PERF_COUNT_HW_MAX
)

const (
	PERF_COUNT_HW_CACHE_L1D uint64 = iota
	PERF_COUNT_HW_CACHE_L1I
	PERF_COUNT_HW_CACHE_LL
	PERF_COUNT_HW_CACHE_DTLB
	PERF_COUNT_HW_CACHE_ITLB
	PERF_COUNT_HW_CACHE_BPU
	PERF_COUNT_HW_CACHE_NODE
	PERF_COUNT_HW_CACHE_MAX
)

const (
	PERF_COUNT_HW_CACHE_OP_READ uint64 = iota
	PERF_COUNT_HW_CACHE_OP_WRITE
	PERF_COUNT_HW_CACHE_OP_PREFETCH
	PERF_COUNT_HW_CACHE_OP_MAX
)

const (
	PERF_COUNT_HW_CACHE_RESULT_ACCESS uint64 = iota
	PERF_COUNT_HW_CACHE_RESULT_MISS
	PERF_COUNT_HW_CACHE_RESULT_MAX
)

const (
	PERF_COUNT_SW_CPU_CLOCK uint64 = iota
	PERF_COUNT_SW_TASK_CLOCK
	PERF_COUNT_SW_PAGE_FAULTS
	PERF_COUNT_SW_CONTEXT_SWITCHES
	PERF_COUNT_SW_CPU_MIGRATIONS
	PERF_COUNT_SW_PAGE_FAULTS_MIN
	PERF_COUNT_SW_PAGE_FAULTS_MAJ
	PERF_COUNT_SW_ALIGNMENT_FAULTS
	PERF_COUNT_SW_EMULATION_FAULTS
	PERF_COUNT_SW_DUMMY
	PERF_COUNT_BPF_OUTPUT
	PERF_COUNT_SW_MAX
)

const (
	PERF_RECORD_INVALID uint32 = iota
	PERF_RECORD_MMAP
	PERF_RECORD_LOST
	PERF_RECORD_COMM
	PERF_RECORD_EXIT
	PERF_RECORD_THROTTLE
	PERF_RECORD_UNTHROTTLE
	PERF_RECORD_FORK
	PERF_RECORD_READ
	PERF_RECORD_SAMPLE
	PERF_RECORD_MMAP2
	PERF_RECORD_AUX
	PERF_RECORD_ITRACE_START
	PERF_RECORD_LOST_SAMPLES
	PERF_RECORD_SWITCH
	PERF_RECORD_SWITCH_CPU_WIDE
	PERF_RECORD_MAX
)

const (
	PERF_SAMPLE_IP uint64 = 1 << iota
	PERF_SAMPLE_TID
	PERF_SAMPLE_TIME
	PERF_SAMPLE_ADDR
	PERF_SAMPLE_READ
	PERF_SAMPLE_CALLCHAIN
	PERF_SAMPLE_ID
	PERF_SAMPLE_CPU
	PERF_SAMPLE_PERIOD
	PERF_SAMPLE_STREAM_ID
	PERF_SAMPLE_RAW
	PERF_SAMPLE_BRANCH_STACK
	PERF_SAMPLE_REGS_USER
	PERF_SAMPLE_STACK_USER
	PERF_SAMPLE_WEIGHT
	PERF_SAMPLE_DATA_SRC
	PERF_SAMPLE_IDENTIFIER
	PERF_SAMPLE_TRANSACTION
	PERF_SAMPLE_REGS_INTR
	PERF_SAMPLE_MAX
)

// Bitmasks for bitfield in EventAttr
const (
	eaDisabled = 1 << iota
	eaInherit
	eaPinned
	eaExclusive
	eaExcludeUser
	eaExcludeKernel
	eaExcludeHV
	eaExcludeIdle
	eaMmap
	eaComm
	eaFreq
	eaInheritStat
	eaEnableOnExec
	eaTask
	eaWatermark
	eaPreciseIP1
	eaPreciseIP2
	eaMmapData
	eaSampleIDAll
	eaExcludeHost
	eaExcludeGuest
	eaExcludeCallchainKernel
	eaExcludeCallchainUser
	eaMmap2
	eaCommExec
	eaUseClockID
	eaContextSwitch
)
