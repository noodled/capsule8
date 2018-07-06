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

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/golang/glog"
)

type readError struct{ error }

func readOrPanic(buf io.Reader, i interface{}) {
	if err := binary.Read(buf, binary.LittleEndian, i); err != nil {
		panic(readError{err})
	}
}

/*
   struct perf_event_attr {
       __u32 type;         // Type of event
       __u32 size;         // Size of attribute structure
       __u64 config;       // Type-specific configuration

       union {
           __u64 sample_period;    // Period of sampling
           __u64 sample_freq;      // Frequency of sampling
       };

       __u64 sample_type;  // Specifies values included in sample
       __u64 read_format;  // Specifies values returned in read

       __u64 disabled       : 1,   // off by default
             inherit        : 1,   // children inherit it
             pinned         : 1,   // must always be on PMU
             exclusive      : 1,   // only group on PMU
             exclude_user   : 1,   // don't count user
             exclude_kernel : 1,   // don't count kernel
             exclude_hv     : 1,   // don't count hypervisor
             exclude_idle   : 1,   // don't count when idle
             mmap           : 1,   // include mmap data
             comm           : 1,   // include comm data
             freq           : 1,   // use freq, not period
             inherit_stat   : 1,   // per task counts
             enable_on_exec : 1,   // next exec enables
             task           : 1,   // trace fork/exit
             watermark      : 1,   // wakeup_watermark
             precise_ip     : 2,   // skid constraint
             mmap_data      : 1,   // non-exec mmap data
             sample_id_all  : 1,   // sample_type all events
             exclude_host   : 1,   // don't count in host
             exclude_guest  : 1,   // don't count in guest
             exclude_callchain_kernel : 1,
                                   // exclude kernel callchains
             exclude_callchain_user   : 1,
                                   // exclude user callchains
             mmap2          :  1,  // include mmap with inode data
             comm_exec      :  1,  // flag comm events that are due to exec
             use_clockid    :  1,  // use clockid for time fields
             context_switch :  1,  // context switch data

             __reserved_1   : 37;

       union {
           __u32 wakeup_events;    // wakeup every n events
           __u32 wakeup_watermark; // bytes before wakeup
       };

       __u32     bp_type;          // breakpoint type

       union {
           __u64 bp_addr;          // breakpoint address
           __u64 config1;          // extension of config
       };

       union {
           __u64 bp_len;           // breakpoint length
           __u64 config2;          // extension of config1
       };
       __u64 branch_sample_type;   // enum perf_branch_sample_type
       __u64 sample_regs_user;     // user regs to dump on samples
       __u32 sample_stack_user;    // size of stack to dump on samples
       __s32 clockid;              // clock to use for time fields
       __u64 sample_regs_intr;     // regs to dump on samples
       __u32 aux_watermark;        // aux bytes before wakeup
       __u16 sample_max_stack;     // max frames in callchain
       __u16 __reserved_2;         // align to u64
   };
*/

// EventAttr is a translation of the Linux kernel's struct perf_event_attr
// into Go. It provides detailed configuration information for the event
// being created.
type EventAttr struct {
	Type                   uint32
	Size                   uint32
	Config                 uint64
	SamplePeriod           uint64
	SampleFreq             uint64
	SampleType             uint64
	ReadFormat             uint64
	Disabled               bool
	Inherit                bool
	Pinned                 bool
	Exclusive              bool
	ExcludeUser            bool
	ExcludeKernel          bool
	ExcludeHV              bool
	ExcludeIdle            bool
	Mmap                   bool
	Comm                   bool
	Freq                   bool
	InheritStat            bool
	EnableOnExec           bool
	Task                   bool
	Watermark              bool
	PreciseIP              uint8
	MmapData               bool
	SampleIDAll            bool
	ExcludeHost            bool
	ExcludeGuest           bool
	ExcludeCallchainKernel bool
	ExcludeCallchainUser   bool
	Mmap2                  bool
	CommExec               bool
	UseClockID             bool
	ContextSwitch          bool
	WakeupEvents           uint32
	WakeupWatermark        uint32
	BPType                 uint32
	BPAddr                 uint64
	Config1                uint64
	BPLen                  uint64
	Config2                uint64
	BranchSampleType       uint64
	SampleRegsUser         uint64
	SampleStackUser        uint32
	ClockID                int32
	SampleRegsIntr         uint64
	AuxWatermark           uint32
	SampleMaxStack         uint16
}

type eventAttrBitfield uint64

func (bf *eventAttrBitfield) setBit(b bool, bit uint64) {
	if b {
		*bf |= eventAttrBitfield(bit)
	}
}

// write serializes the EventAttr as a perf_event_attr struct compatible
// with the kernel.
func (ea *EventAttr) write(buf io.Writer) error {
	// Automatically figure out ea.Size; ignore whatever is passed in.
	switch {
	case ea.AuxWatermark > 0 || ea.SampleMaxStack > 0:
		ea.Size = sizeofPerfEventAttrVer5
	case ea.SampleType&PERF_SAMPLE_REGS_INTR != 0:
		ea.Size = sizeofPerfEventAttrVer4
	case ea.UseClockID || ea.SampleType&(PERF_SAMPLE_REGS_USER|PERF_SAMPLE_STACK_USER) != 0:
		ea.Size = sizeofPerfEventAttrVer3
	case ea.SampleType&PERF_SAMPLE_BRANCH_STACK != 0:
		ea.Size = sizeofPerfEventAttrVer2
	case ea.Type == PERF_TYPE_BREAKPOINT || ea.Config2 != 0:
		ea.Size = sizeofPerfEventAttrVer1
	default:
		ea.Size = sizeofPerfEventAttrVer0
	}

	binary.Write(buf, binary.LittleEndian, ea.Type)
	binary.Write(buf, binary.LittleEndian, ea.Size)
	binary.Write(buf, binary.LittleEndian, ea.Config)

	if (ea.Freq && ea.SamplePeriod != 0) ||
		(!ea.Freq && ea.SampleFreq != 0) {
		return errors.New("Encoding error: invalid SamplePeriod/SampleFreq union")
	}

	if ea.Freq {
		binary.Write(buf, binary.LittleEndian, ea.SampleFreq)
	} else {
		binary.Write(buf, binary.LittleEndian, ea.SamplePeriod)
	}

	binary.Write(buf, binary.LittleEndian, ea.SampleType)
	binary.Write(buf, binary.LittleEndian, ea.ReadFormat)

	if ea.PreciseIP > 3 {
		return errors.New("Encoding error: PreciseIP must be < 4")
	}

	var bitfield eventAttrBitfield
	bitfield.setBit(ea.Disabled, eaDisabled)
	bitfield.setBit(ea.Inherit, eaInherit)
	bitfield.setBit(ea.Pinned, eaPinned)
	bitfield.setBit(ea.Exclusive, eaExclusive)
	bitfield.setBit(ea.ExcludeUser, eaExcludeUser)
	bitfield.setBit(ea.ExcludeKernel, eaExcludeKernel)
	bitfield.setBit(ea.ExcludeHV, eaExcludeHV)
	bitfield.setBit(ea.ExcludeIdle, eaExcludeIdle)
	bitfield.setBit(ea.Mmap, eaMmap)
	bitfield.setBit(ea.Comm, eaComm)
	bitfield.setBit(ea.Freq, eaFreq)
	bitfield.setBit(ea.InheritStat, eaInheritStat)
	bitfield.setBit(ea.EnableOnExec, eaEnableOnExec)
	bitfield.setBit(ea.Task, eaTask)
	bitfield.setBit(ea.Watermark, eaWatermark)
	bitfield.setBit(ea.PreciseIP&0x1 == 0x1, eaPreciseIP1)
	bitfield.setBit(ea.PreciseIP&0x2 == 0x2, eaPreciseIP2)
	bitfield.setBit(ea.MmapData, eaMmapData)
	bitfield.setBit(ea.SampleIDAll, eaSampleIDAll)
	bitfield.setBit(ea.ExcludeHost, eaExcludeHost)
	bitfield.setBit(ea.ExcludeGuest, eaExcludeGuest)
	bitfield.setBit(ea.ExcludeCallchainKernel, eaExcludeCallchainKernel)
	bitfield.setBit(ea.ExcludeCallchainUser, eaExcludeCallchainUser)
	bitfield.setBit(ea.Mmap2, eaMmap2)
	bitfield.setBit(ea.CommExec, eaCommExec)
	bitfield.setBit(ea.UseClockID, eaUseClockID)
	bitfield.setBit(ea.ContextSwitch, eaContextSwitch)
	binary.Write(buf, binary.LittleEndian, uint64(bitfield))

	if (ea.Watermark && ea.WakeupEvents != 0) ||
		(!ea.Watermark && ea.WakeupWatermark != 0) {
		return errors.New("Encoding error: invalid WakeupWatermark/WakeupEvents union")
	}

	if ea.Watermark {
		binary.Write(buf, binary.LittleEndian, ea.WakeupWatermark)
	} else {
		binary.Write(buf, binary.LittleEndian, ea.WakeupEvents)
	}

	binary.Write(buf, binary.LittleEndian, ea.BPType)

	switch ea.Type {
	case PERF_TYPE_BREAKPOINT:
		if ea.Config1 != 0 || ea.Config2 != 0 {
			return errors.New("Cannot set Config1/Config2 for type == PERF_TYPE_BREAKPOINT")
		}
		binary.Write(buf, binary.LittleEndian, ea.BPAddr)
		binary.Write(buf, binary.LittleEndian, ea.BPLen)
	default:
		if ea.BPAddr != 0 || ea.BPLen != 0 {
			return errors.New("Cannot set BPAddr/BPLen for type != PERF_TYPE_BREAKPOINT")
		}
		binary.Write(buf, binary.LittleEndian, ea.Config1)
		binary.Write(buf, binary.LittleEndian, ea.Config2)
	}

	binary.Write(buf, binary.LittleEndian, ea.BranchSampleType)
	binary.Write(buf, binary.LittleEndian, ea.SampleRegsUser)
	binary.Write(buf, binary.LittleEndian, ea.SampleStackUser)
	binary.Write(buf, binary.LittleEndian, ea.ClockID)
	binary.Write(buf, binary.LittleEndian, ea.SampleRegsIntr)
	binary.Write(buf, binary.LittleEndian, ea.AuxWatermark)
	binary.Write(buf, binary.LittleEndian, ea.SampleMaxStack)

	binary.Write(buf, binary.LittleEndian, uint16(0))

	return nil
}

/*
   struct perf_event_mmap_page {
       __u32 version;        // version number of this structure
       __u32 compat_version; // lowest version this is compat with
       __u32 lock;           // seqlock for synchronization
       __u32 index;          // hardware counter identifier
       __s64 offset;         // add to hardware counter value
       __u64 time_enabled;   // time event active
       __u64 time_running;   // time event on CPU
       union {
           __u64   capabilities;
           struct {
               __u64 cap_usr_time / cap_usr_rdpmc / cap_bit0 : 1,
                     cap_bit0_is_deprecated : 1,
                     cap_user_rdpmc         : 1,
                     cap_user_time          : 1,
                     cap_user_time_zero     : 1,
           };
       };
       __u16 pmc_width;
       __u16 time_shift;
       __u32 time_mult;
       __u64 time_offset;
       __u64 __reserved[120];   // Pad to 1k
       __u64 data_head;         // head in the data section
       __u64 data_tail;         // user-space written tail
       __u64 data_offset;       // where the buffer starts
       __u64 data_size;         // data buffer size
       __u64 aux_head;
       __u64 aux_tail;
       __u64 aux_offset;
       __u64 aux_size;
   }
*/

type metadata struct {
	Version       uint32
	CompatVersion uint32
	Lock          uint32
	Index         uint32
	Offset        int64
	TimeEnabled   uint64
	TimeRunning   uint64
	Capabilities  uint64
	PMCWidth      uint16
	TimeWidth     uint16
	TimeMult      uint32
	TimeOffset    uint64
	_             [120]uint64
	DataHead      uint64
	DataTail      uint64
	DataOffset    uint64
	DataSize      uint64
	AuxHead       uint64
	AuxTail       uint64
	AuxOffset     uint64
	AuxSize       uint64
}

// -----------------------------------------------------------------------------

/*
   struct perf_event_header {
       __u32   type;
       __u16   misc;
       __u16   size;
   };
*/

type eventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

const sizeofEventHeader = 8

func (eh *eventHeader) read(reader io.Reader) error {
	return binary.Read(reader, binary.LittleEndian, eh)
}

// CommRecord is a translation of the structure used by the Linux kernel for
// PERF_RECORD_COMM samples into Go.
type CommRecord struct {
	Pid  uint32
	Tid  uint32
	Comm []byte
}

// Fixed portion + at least 8 for Comm
const sizeofCommRecord = 8

func (cr *CommRecord) read(reader io.Reader) {
	readOrPanic(reader, &cr.Pid)
	readOrPanic(reader, &cr.Tid)

	for {
		var b byte
		readOrPanic(reader, &b)
		if b == 0 {
			break
		}
		cr.Comm = append(cr.Comm, b)
	}

	// The comm[] field is NULL-padded up to an 8-byte aligned
	// offset. Discard the rest of the bytes.
	i := 8 - ((len(cr.Comm) + 1) % 8)
	if i < 8 {
		readOrPanic(reader, make([]byte, i))
	}
}

// ExitRecord is a translation of the structure used by the Linux kernel for
// PERF_RECORD_EXIT samples into Go.
type ExitRecord struct {
	Pid  uint32
	Ppid uint32
	Tid  uint32
	Ptid uint32
	Time uint64
}

const sizeofExitRecord = 24

func (er *ExitRecord) read(reader io.Reader) {
	readOrPanic(reader, &er.Pid)
	readOrPanic(reader, &er.Ppid)
	readOrPanic(reader, &er.Tid)
	readOrPanic(reader, &er.Ptid)
	readOrPanic(reader, &er.Time)
}

// LostRecord is a translation of the structure used by the Linux kernel for
// PERF_RECORD_LOST samples into Go.
type LostRecord struct {
	ID   uint64
	Lost uint64
}

const sizeofLostRecord = 16

func (lr *LostRecord) read(reader io.Reader) {
	readOrPanic(reader, &lr.ID)
	readOrPanic(reader, &lr.Lost)
}

// ForkRecord is a translation of the structure used by the Linux kernel for
// PERF_RECORD_FORK samples into Go.
type ForkRecord struct {
	Pid  uint32
	Ppid uint32
	Tid  uint32
	Ptid uint32
	Time uint64
}

const sizeofForkRecord = 24

func (fr *ForkRecord) read(reader io.Reader) {
	readOrPanic(reader, &fr.Pid)
	readOrPanic(reader, &fr.Ppid)
	readOrPanic(reader, &fr.Tid)
	readOrPanic(reader, &fr.Ptid)
	readOrPanic(reader, &fr.Time)
}

// TraceEvent represents the common header on all trace events
type TraceEvent struct {
	Type         uint16
	Flags        uint8
	PreemptCount uint8
	Pid          int32
}

// CounterValue resepresents the read value of a counter event
type CounterValue struct {
	// Globally unique identifier for this counter event. Only
	// present if PERF_FORMAT_ID was specified.
	ID uint64

	// The counter result
	Value uint64
}

// CounterGroup represents the read values of a group of counter events
type CounterGroup struct {
	TimeEnabled uint64
	TimeRunning uint64
	Values      []CounterValue
}

func (cg *CounterGroup) read(reader io.Reader, format uint64) {
	if (format & PERF_FORMAT_GROUP) != 0 {
		var nr uint64
		readOrPanic(reader, &nr)

		if (format & PERF_FORMAT_TOTAL_TIME_ENABLED) != 0 {
			readOrPanic(reader, &cg.TimeEnabled)
		}

		if (format & PERF_FORMAT_TOTAL_TIME_RUNNING) != 0 {
			readOrPanic(reader, &cg.TimeRunning)
		}

		for i := uint64(0); i < nr; i++ {
			value := CounterValue{}

			readOrPanic(reader, &value.Value)

			if (format & PERF_FORMAT_ID) != 0 {
				readOrPanic(reader, &value.ID)
			}

			cg.Values = append(cg.Values, value)
		}
	} else {
		value := CounterValue{}

		readOrPanic(reader, &value.Value)

		if (format & PERF_FORMAT_TOTAL_TIME_ENABLED) != 0 {
			readOrPanic(reader, &cg.TimeEnabled)
		}

		if (format & PERF_FORMAT_TOTAL_TIME_RUNNING) != 0 {
			readOrPanic(reader, &cg.TimeRunning)
		}

		if (format & PERF_FORMAT_ID) != 0 {
			readOrPanic(reader, &value.ID)
		}

		cg.Values = append(cg.Values, value)
	}
}

// BranchEntry is a translation of the Linux kernel's struct perf_branch_entry
// into Go. It may appear in SampleRecord if PERF_SAMPLE_BRANCH_STACK is set.
type BranchEntry struct {
	From      uint64
	To        uint64
	Mispred   bool
	Predicted bool
	InTx      bool
	Abort     bool
	Cycles    uint16
}

// SampleRecord is a translation of the structure used by the Linux kernel for
// PERF_RECORD_SAMPLE samples into Go.
type SampleRecord struct {
	SampleID    uint64
	IP          uint64
	Pid         uint32
	Tid         uint32
	Time        uint64
	Addr        uint64
	ID          uint64
	StreamID    uint64
	CPU         uint32
	Period      uint64
	V           CounterGroup
	IPs         []uint64
	RawData     []byte
	Branches    []BranchEntry
	UserABI     uint64
	UserRegs    []uint64
	StackData   []uint64
	Weight      uint64
	DataSrc     uint64
	Transaction uint64
	IntrABI     uint64
	IntrRegs    []uint64
}

func (s *SampleRecord) read(
	reader io.Reader,
	eventAttr *EventAttr,
) {
	sampleType := eventAttr.SampleType

	// Clear PERF_SAMPLE_IDENTIFIER because that should have already been
	// read. Leaving it set will cause problems in the sanity check below
	// just before returning.
	sampleType &= ^PERF_SAMPLE_IDENTIFIER

	if sampleType&PERF_SAMPLE_IP != 0 {
		sampleType &= ^PERF_SAMPLE_IP
		readOrPanic(reader, &s.IP)
	}

	if sampleType&PERF_SAMPLE_TID != 0 {
		sampleType &= ^PERF_SAMPLE_TID
		readOrPanic(reader, &s.Pid)
		readOrPanic(reader, &s.Tid)
	}

	if sampleType&PERF_SAMPLE_TIME != 0 {
		sampleType &= ^PERF_SAMPLE_TIME
		readOrPanic(reader, &s.Time)
	}

	if sampleType&PERF_SAMPLE_ADDR != 0 {
		sampleType &= ^PERF_SAMPLE_ADDR
		readOrPanic(reader, &s.Addr)
	}

	if sampleType&PERF_SAMPLE_ID != 0 {
		sampleType &= ^PERF_SAMPLE_ID
		readOrPanic(reader, &s.ID)
	}

	if sampleType&PERF_SAMPLE_STREAM_ID != 0 {
		sampleType &= ^PERF_SAMPLE_STREAM_ID
		readOrPanic(reader, &s.StreamID)
	}

	if sampleType&PERF_SAMPLE_CPU != 0 {
		sampleType &= ^PERF_SAMPLE_CPU
		var res uint32
		readOrPanic(reader, &s.CPU)
		readOrPanic(reader, &res)
	}

	if sampleType&PERF_SAMPLE_PERIOD != 0 {
		sampleType &= ^PERF_SAMPLE_PERIOD
		readOrPanic(reader, &s.Period)
	}

	if sampleType&PERF_SAMPLE_READ != 0 {
		sampleType &= ^PERF_SAMPLE_READ
		s.V.read(reader, eventAttr.ReadFormat)
	}

	if sampleType&PERF_SAMPLE_CALLCHAIN != 0 {
		sampleType &= ^PERF_SAMPLE_CALLCHAIN
		var nr uint64
		readOrPanic(reader, &nr)
		s.IPs = make([]uint64, 0, nr)
		for i := uint64(0); i < nr; i++ {
			var ip uint64
			readOrPanic(reader, &ip)
			s.IPs = append(s.IPs, ip)
		}
	}

	if sampleType&PERF_SAMPLE_RAW != 0 {
		sampleType &= ^PERF_SAMPLE_RAW
		var rawDataSize uint32
		readOrPanic(reader, &rawDataSize)
		s.RawData = make([]byte, rawDataSize)
		readOrPanic(reader, s.RawData)
	}

	if sampleType&PERF_SAMPLE_BRANCH_STACK != 0 {
		sampleType &= ^PERF_SAMPLE_BRANCH_STACK
		var bnr uint64
		readOrPanic(reader, &bnr)
		s.Branches = make([]BranchEntry, 0, bnr)
		for i := uint64(0); i < bnr; i++ {
			var pbe struct {
				From  uint64
				To    uint64
				Flags uint64
			}
			readOrPanic(reader, &pbe)

			branchEntry := BranchEntry{
				From:      pbe.From,
				To:        pbe.To,
				Mispred:   (pbe.Flags&(1<<0) != 0),
				Predicted: (pbe.Flags&(1<<1) != 0),
				InTx:      (pbe.Flags&(1<<2) != 0),
				Abort:     (pbe.Flags&(1<<3) != 0),
				Cycles:    uint16((pbe.Flags & 0xffff0) >> 4),
			}
			s.Branches = append(s.Branches, branchEntry)
		}
	}

	if sampleType != 0 {
		panic(fmt.Sprintf("EventAttr.SampleType has unsupported bits %x set", sampleType))
	}
}

/*
   struct sample_id {
       { u32 pid, tid; } // if PERF_SAMPLE_TID set
       { u64 time;     } // if PERF_SAMPLE_TIME set
       { u64 id;       } // if PERF_SAMPLE_ID set
       { u64 stream_id;} // if PERF_SAMPLE_STREAM_ID set
       { u32 cpu, res; } // if PERF_SAMPLE_CPU set
       { u64 id;       } // if PERF_SAMPLE_IDENTIFIER set
   };
*/

// SampleID is a translation of the structure used by the Linux kernel for all
// samples when SampleIDAll is set in the EventAttr used for a sample.
type SampleID struct {
	PID      uint32
	TID      uint32
	Time     uint64
	ID       uint64
	StreamID uint64
	CPU      uint32
}

var sampleIDSizeCache atomic.Value
var sampleIDSizeCacheMutex sync.Mutex

func (sid *SampleID) getSize(eventSampleType uint64, eventSampleIDAll bool) int {
	if sizeCache := sampleIDSizeCache.Load(); sizeCache != nil {
		cache := sizeCache.(map[uint64]int)
		if size, ok := cache[eventSampleType]; ok {
			return size
		}
	}

	var size int
	if eventSampleIDAll {
		if (eventSampleType & PERF_SAMPLE_TID) != 0 {
			size += binary.Size(sid.PID)
			size += binary.Size(sid.TID)
		}

		if (eventSampleType & PERF_SAMPLE_TIME) != 0 {
			size += binary.Size(sid.Time)
		}

		if (eventSampleType & PERF_SAMPLE_ID) != 0 {
			size += binary.Size(sid.ID)
		}

		if (eventSampleType & PERF_SAMPLE_STREAM_ID) != 0 {
			size += binary.Size(sid.StreamID)
		}

		if (eventSampleType & PERF_SAMPLE_CPU) != 0 {
			size += binary.Size(sid.CPU)
			size += binary.Size(uint32(0))
		}

		if (eventSampleType & PERF_SAMPLE_IDENTIFIER) != 0 {
			size += binary.Size(sid.ID)
		}
	}

	var newCache map[uint64]int
	sampleIDSizeCacheMutex.Lock()
	if sizeCache := sampleIDSizeCache.Load(); sizeCache == nil {
		newCache = make(map[uint64]int)
	} else {
		oldCache := sizeCache.(map[uint64]int)
		newCache = make(map[uint64]int, len(oldCache)+1)
		for k, v := range oldCache {
			newCache[k] = v
		}
	}
	newCache[eventSampleType] = size
	sampleIDSizeCache.Store(newCache)
	sampleIDSizeCacheMutex.Unlock()

	return size
}

func (sid *SampleID) read(reader io.Reader, eventSampleType uint64) {
	if (eventSampleType & PERF_SAMPLE_TID) != 0 {
		readOrPanic(reader, &sid.PID)
		readOrPanic(reader, &sid.TID)
	}

	if (eventSampleType & PERF_SAMPLE_TIME) != 0 {
		readOrPanic(reader, &sid.Time)
	}

	if (eventSampleType & PERF_SAMPLE_ID) != 0 {
		readOrPanic(reader, &sid.ID)
	}

	if (eventSampleType & PERF_SAMPLE_STREAM_ID) != 0 {
		readOrPanic(reader, &sid.StreamID)
	}

	if (eventSampleType & PERF_SAMPLE_CPU) != 0 {
		var res uint32
		readOrPanic(reader, &sid.CPU)
		readOrPanic(reader, &res)
	}

	if (eventSampleType & PERF_SAMPLE_IDENTIFIER) != 0 {
		readOrPanic(reader, &sid.ID)
	}
}

// Sample is the representation of a perf_event sample retrieved from the
// Linux kernel. It includes the header information, a translation of the
// sample data, and metadata depending on the flags set in the EventAttr
// used to enable the event that generated the sample.
type Sample struct {
	eventHeader
	Record interface{}
	SampleID
}

func (sample *Sample) resolveEventAttr(
	reader io.ReadSeeker,
	startPos int64,
	eventAttr *EventAttr,
	formatMap map[uint64]*EventAttr,
) (uint64, *EventAttr) {
	// Assumptions: All EventAttr structures in use must have following
	// set for any of this code to function properly:
	//
	//	SampleType |= PERF_SAMPLE_IDENTIFIER
	//      SampleIDAll = true
	//
	// If we're finding the eventAttr from formatMap, the sample ID will be
	// in the record where it's needed. For PERF_RECORD_SAMPLE, the ID will
	// be the first thing in the data. For everything else, the ID will be
	// the last thing in the data.
	var sampleID uint64
	if sample.Type == PERF_RECORD_SAMPLE {
		readOrPanic(reader, &sampleID)
	} else {
		// Move to the end of the record and read the sampleID from
		// there, then jump back to the current position.
		// currentPos - startPos == # bytes already read
		currentPos, _ := reader.Seek(0, os.SEEK_CUR)
		if currentPos-startPos == int64(sample.Size) {
			return 0, nil
		}
		if currentPos-startPos > int64(sample.Size) {
			panic("internal error - read too much data!")
		}
		if int64(sample.Size)-(currentPos-startPos) < 8 {
			panic("internal error - not enough data left to read for SampleIDAll!")
		}

		reader.Seek(currentPos+int64(sample.Size)-8, os.SEEK_SET)
		readOrPanic(reader, &sampleID)
		reader.Seek(currentPos, os.SEEK_SET)
	}

	if eventAttr != nil {
		return sampleID, eventAttr
	}

	eventAttr, ok := formatMap[sampleID]
	if !ok {
		panic(readError{fmt.Errorf("Unknown SampleID %d from raw sample", sampleID)})
	}
	if !eventAttr.SampleIDAll {
		panic("SampleIDAll not specified in EventAttr")
	}
	if eventAttr.SampleType&PERF_SAMPLE_IDENTIFIER == 0 {
		panic("PERF_SAMPLE_IDENTIFIER not specified in EventAttr")
	}

	return sampleID, eventAttr
}

func (sample *Sample) read(
	reader io.ReadSeeker,
	eventAttr *EventAttr,
	formatMap map[uint64]*EventAttr,
) (err error) {
	startPos, _ := reader.Seek(0, os.SEEK_CUR)

	if err = sample.eventHeader.read(reader); err != nil {
		// This is not recoverable
		panic("Could not read perf event header")
	}

	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(readError); ok {
				err = e.error
				reader.Seek((startPos + int64(sample.Size)), os.SEEK_SET)
			} else {
				panic(r)
			}
		}
	}()

	var sampleID uint64
	if eventAttr == nil {
		sampleID, eventAttr = sample.resolveEventAttr(
			reader, startPos, eventAttr, formatMap)
		if eventAttr == nil {
			return nil
		}
	} else if sample.Type == PERF_RECORD_SAMPLE {
		readOrPanic(reader, &sampleID)
	} // else SampleID is unknown

	switch sample.Type {
	case PERF_RECORD_FORK:
		record := &ForkRecord{}
		record.read(reader)
		sample.Record = record
		if eventAttr.SampleIDAll {
			sample.SampleID.read(reader, eventAttr.SampleType)
		}

	case PERF_RECORD_EXIT:
		record := &ExitRecord{}
		record.read(reader)
		sample.Record = record
		if eventAttr.SampleIDAll {
			sample.SampleID.read(reader, eventAttr.SampleType)
		}

	case PERF_RECORD_COMM:
		record := &CommRecord{}
		record.read(reader)
		sample.Record = record
		if eventAttr.SampleIDAll {
			sample.SampleID.read(reader, eventAttr.SampleType)
		}

	case PERF_RECORD_SAMPLE:
		record := &SampleRecord{
			SampleID: sampleID,
		}
		record.read(reader, eventAttr)
		sample.Record = record

		// NB: PERF_RECORD_SAMPLE does not include a trailing
		// SampleID, even if SampleIDAll is true.
		// Fill in the missing information from SampleRecord so that
		// it's complete to the outside observer
		sample.SampleID = SampleID{
			PID:      record.Pid,
			TID:      record.Tid,
			Time:     record.Time,
			ID:       record.ID,
			StreamID: record.StreamID,
			CPU:      record.CPU,
		}

	case PERF_RECORD_LOST:
		record := &LostRecord{}
		record.read(reader)
		sample.Record = record
		if eventAttr.SampleIDAll {
			sample.SampleID.read(reader, eventAttr.SampleType)
		}

	default:
		// Unknown type, read sample record as a byte slice
		recordSize := sample.Size - uint16(binary.Size(sample.eventHeader))

		if eventAttr != nil {
			sampleIDSize := sample.SampleID.getSize(eventAttr.SampleType, eventAttr.SampleIDAll)
			recordSize -= uint16(sampleIDSize)
		}

		recordData := make([]byte, recordSize)

		var n int
		if n, err = reader.Read(recordData); err != nil {
			panic(readError{err})
		}
		if n < int(recordSize) {
			glog.Infof("Short read: %d < %d", n, int(recordSize))
			panic(readError{errors.New("Read error")})
		}

		sample.Record = recordData
	}

	return
}
