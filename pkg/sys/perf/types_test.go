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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
)

func (bf *eventAttrBitfield) testBit(bit uint64) bool {
	return *bf&eventAttrBitfield(bit) == eventAttrBitfield(bit)
}

func (ea *EventAttr) read(buf io.Reader) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(readError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	*ea = EventAttr{} // zero everything out

	readOrPanic(buf, &ea.Type)

	readOrPanic(buf, &ea.Size)
	switch ea.Size {
	case sizeofPerfEventAttrVer0,
		sizeofPerfEventAttrVer1,
		sizeofPerfEventAttrVer2,
		sizeofPerfEventAttrVer3,
		sizeofPerfEventAttrVer4,
		sizeofPerfEventAttrVer5:
		// pass
	default:
		return fmt.Errorf("Illegal size %d while reading EventAttr", ea.Size)
	}

	readOrPanic(buf, &ea.Config)

	// Don't know which to use, SamplePeriod or SampleFreq until flags are
	// read after this. Read now and assign later.
	var samplePeriodOrFreq uint64
	readOrPanic(buf, &samplePeriodOrFreq)

	readOrPanic(buf, &ea.SampleType)
	readOrPanic(buf, &ea.ReadFormat)

	var uint64Value uint64
	readOrPanic(buf, &uint64Value)
	bitfield := eventAttrBitfield(uint64Value)
	ea.Disabled = bitfield.testBit(eaDisabled)
	ea.Inherit = bitfield.testBit(eaInherit)
	ea.Pinned = bitfield.testBit(eaPinned)
	ea.Exclusive = bitfield.testBit(eaExclusive)
	ea.ExcludeUser = bitfield.testBit(eaExcludeUser)
	ea.ExcludeKernel = bitfield.testBit(eaExcludeKernel)
	ea.ExcludeHV = bitfield.testBit(eaExcludeHV)
	ea.ExcludeIdle = bitfield.testBit(eaExcludeIdle)
	ea.Mmap = bitfield.testBit(eaMmap)
	ea.Comm = bitfield.testBit(eaComm)
	ea.Freq = bitfield.testBit(eaFreq)
	ea.InheritStat = bitfield.testBit(eaInheritStat)
	ea.EnableOnExec = bitfield.testBit(eaEnableOnExec)
	ea.Task = bitfield.testBit(eaTask)
	ea.Watermark = bitfield.testBit(eaWatermark)
	if bitfield.testBit(eaPreciseIP1) {
		ea.PreciseIP |= 0x1
	}
	if bitfield.testBit(eaPreciseIP2) {
		ea.PreciseIP |= 0x2
	}
	ea.MmapData = bitfield.testBit(eaMmapData)
	ea.SampleIDAll = bitfield.testBit(eaSampleIDAll)
	ea.ExcludeHost = bitfield.testBit(eaExcludeHost)
	ea.ExcludeGuest = bitfield.testBit(eaExcludeGuest)
	ea.ExcludeCallchainKernel = bitfield.testBit(eaExcludeCallchainKernel)
	ea.ExcludeCallchainUser = bitfield.testBit(eaExcludeCallchainUser)
	ea.Mmap2 = bitfield.testBit(eaMmap2)
	ea.CommExec = bitfield.testBit(eaCommExec)
	ea.UseClockID = bitfield.testBit(eaUseClockID)
	ea.ContextSwitch = bitfield.testBit(eaContextSwitch)

	if ea.Freq {
		ea.SampleFreq = samplePeriodOrFreq
	} else {
		ea.SamplePeriod = samplePeriodOrFreq
	}

	if ea.Watermark {
		readOrPanic(buf, &ea.WakeupWatermark)
	} else {
		readOrPanic(buf, &ea.WakeupEvents)
	}

	readOrPanic(buf, &ea.BPType)

	// Things start getting funky from here on out due to sizes and field
	// use changes, etc.

	if ea.Size < sizeofPerfEventAttrVer1 {
		if ea.Type == PERF_TYPE_BREAKPOINT {
			return errors.New("EventAttr struct too small for PERF_TYPE_BREAKPOINT")
		}
		return nil
	}

	if ea.Type == PERF_TYPE_BREAKPOINT {
		readOrPanic(buf, &ea.BPAddr)
		readOrPanic(buf, &ea.BPLen)
	} else {
		readOrPanic(buf, &ea.Config1)
		readOrPanic(buf, &ea.Config2)
	}

	if ea.Size < sizeofPerfEventAttrVer2 {
		if ea.SampleType&PERF_SAMPLE_BRANCH_STACK != 0 {
			return errors.New("EventAttr struct too small for PERF_SAMPLE_BRANCH_STACK")
		}
		return nil
	}

	readOrPanic(buf, &ea.BranchSampleType)

	if ea.Size < sizeofPerfEventAttrVer3 {
		if ea.SampleType&PERF_SAMPLE_REGS_USER != 0 {
			return errors.New("EventAttr struct too small for PERF_SAMPLE_REGS_USER")
		}
		if ea.SampleType&PERF_SAMPLE_STACK_USER != 0 {
			return errors.New("EventAttr struct too small for PERF_SAMPLE_STACK_USER")
		}
		if ea.UseClockID {
			return errors.New("EventAttr struct too small for UseClockID == true")
		}
		return nil
	}

	readOrPanic(buf, &ea.SampleRegsUser)
	readOrPanic(buf, &ea.SampleStackUser)
	readOrPanic(buf, &ea.ClockID)

	if ea.Size < sizeofPerfEventAttrVer4 {
		if ea.SampleType&PERF_SAMPLE_REGS_INTR != 0 {
			return errors.New("EventAttr struct too small for PERF_SAMPLE_REGS_INTR")
		}
		return nil
	}

	readOrPanic(buf, &ea.SampleRegsIntr)

	if ea.Size < sizeofPerfEventAttrVer5 {
		return nil
	}

	readOrPanic(buf, &ea.AuxWatermark)
	readOrPanic(buf, &ea.SampleMaxStack)

	var reserved uint16
	readOrPanic(buf, &reserved)

	return
}

func TestEventAttrWriteSizes(t *testing.T) {
	// The first tests check to ensure that sizes are chosen correctly.
	// Sizes are chosen based on fields in use. New fields have been added
	// in different kernel versions.
	type sizeTestCase struct {
		size uint32
		attr EventAttr
	}
	sizeTestCases := []sizeTestCase{
		// First published struct
		sizeTestCase{
			sizeofPerfEventAttrVer0,
			EventAttr{},
		},

		// add: config2
		sizeTestCase{
			sizeofPerfEventAttrVer1,
			EventAttr{
				Config2: 8,
			},
		},

		// add: branch_sample_type
		// -- ignored if PERF_SAMPLE_BRANCH_STACK not set in SampleType
		sizeTestCase{
			sizeofPerfEventAttrVer2,
			EventAttr{
				SampleType: PERF_SAMPLE_BRANCH_STACK,
			},
		},

		// add: sample_regs_user, sample_stack_user
		// -- ignored if neither PERF_SAMPLE_REGS_USER nor
		//    PERF_SAMPLE_STACK_USER are set in SampleType
		// -- UseClockID enables use of reserved field added here,
		//    later renamed to clockid in 4.1
		sizeTestCase{
			sizeofPerfEventAttrVer3,
			EventAttr{
				SampleType: PERF_SAMPLE_REGS_USER,
			},
		},
		sizeTestCase{
			sizeofPerfEventAttrVer3,
			EventAttr{
				SampleType: PERF_SAMPLE_STACK_USER,
			},
		},
		sizeTestCase{
			sizeofPerfEventAttrVer3,
			EventAttr{
				UseClockID: true,
			},
		},

		// add: sample_regs_intr
		// -- ignored if PERF_SAMPLE_REGS_INTR not set in SampleType
		sizeTestCase{
			sizeofPerfEventAttrVer4,
			EventAttr{
				SampleType: PERF_SAMPLE_REGS_INTR,
			},
		},

		// add: aux_watermark
		// -- sample_max_stack added later, but uses a reserved field
		//    included with the addition of aux_watermark, so both use
		//    the same size
		sizeTestCase{
			sizeofPerfEventAttrVer5,
			EventAttr{
				AuxWatermark: 468237,
			},
		},
		sizeTestCase{
			sizeofPerfEventAttrVer5,
			EventAttr{
				SampleMaxStack: 32768,
			},
		},
	}
	for _, tc := range sizeTestCases {
		writeBuffer := &bytes.Buffer{}
		err := tc.attr.write(writeBuffer)
		ok(t, err)

		var actualSize, actualType uint32
		readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
		binary.Read(readBuffer, binary.LittleEndian, &actualType)
		binary.Read(readBuffer, binary.LittleEndian, &actualSize)

		assert(t, actualSize == tc.size,
			"wrong size (expected %d; got %d)", tc.size, actualSize)

		// Don't check the exact size of the write buffer here since
		// all fields are always written. But the length should be at
		// least as long as the size.
		assert(t, actualSize <= uint32(writeBuffer.Len()),
			"bytes written does not match attr.Size (expected %d; got %d)",
			actualSize, writeBuffer.Len())
	}
}

func TestEventAttrWriteFailures(t *testing.T) {
	// These failure cases are not exhaustive.
	failAttrs := []EventAttr{
		EventAttr{
			Freq:       false,
			SampleFreq: 1,
		},
		EventAttr{
			Freq:         true,
			SamplePeriod: 1,
		},
		EventAttr{
			Watermark:       false,
			WakeupWatermark: 1,
		},
		EventAttr{
			Watermark:    true,
			WakeupEvents: 1,
		},
		EventAttr{
			Type:    PERF_TYPE_BREAKPOINT,
			Config1: 1,
		},
		EventAttr{
			Type:    PERF_TYPE_BREAKPOINT,
			Config2: 1,
		},
		EventAttr{
			Type:   PERF_TYPE_TRACEPOINT,
			BPAddr: 1,
		},
		EventAttr{
			Type:  PERF_TYPE_HARDWARE,
			BPLen: 1,
		},
		EventAttr{
			PreciseIP: 4,
		},
	}
	for _, attr := range failAttrs {
		writeBuffer := &bytes.Buffer{}
		err := attr.write(writeBuffer)
		assert(t, err != nil, "expected error for %+v", attr)
	}
}

func TestEventAttrWriteContent(t *testing.T) {
	testCases := []EventAttr{
		// Ensure the Freq flag does what it's supposed to
		EventAttr{
			Freq:       true,
			SampleFreq: 827634,
		},
		EventAttr{
			Freq:         false,
			SamplePeriod: 298347,
		},
		// Quick checks for all possible PreciseIP values
		EventAttr{PreciseIP: 1},
		EventAttr{PreciseIP: 2},
		EventAttr{PreciseIP: 3},
		// Ensure the Watermark flag does what it's supposed to
		EventAttr{
			Watermark:       true,
			WakeupWatermark: 293478,
		},
		EventAttr{
			Watermark:    false,
			WakeupEvents: 7834,
		},
		// Ensure proper handling for PERF_TYPE_BREAKPOINT
		EventAttr{
			Type:   PERF_TYPE_BREAKPOINT,
			BPAddr: 249378,
			BPLen:  23467,
		},
		EventAttr{
			Type:    PERF_TYPE_RAW,
			Config1: 2367,
			Config2: 945367,
		},
		// Various checks for Type, Config, SampleType, ReadFormat
		EventAttr{
			Type:             PERF_TYPE_HW_CACHE,
			Config:           942783,
			SampleType:       71253,
			ReadFormat:       57698,
			BPType:           32467,
			BranchSampleType: 236745,
			SampleRegsUser:   3247,
			SampleStackUser:  34785,
			ClockID:          498,
			SampleRegsIntr:   91823,
			AuxWatermark:     923,
			SampleMaxStack:   9685,
		},
	}

	for _, expectedAttr := range testCases {
		writeBuffer := &bytes.Buffer{}
		err := expectedAttr.write(writeBuffer)
		assert(t, err == nil, "unexpected error for %+v: %v", expectedAttr, err)

		var actualAttr EventAttr
		readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
		err = actualAttr.read(readBuffer)
		assert(t, err == nil, "unexpected error for %+v: %v", expectedAttr, err)

		assert(t, reflect.DeepEqual(expectedAttr, actualAttr),
			"\n\n\texp: %#v\n\n\tgot: %#v\n\n", expectedAttr, actualAttr)
	}

	bitfieldNames := []string{
		"Disabled", "Inherit", "Pinned", "Exclusive", "ExcludeUser",
		"ExcludeKernel", "ExcludeHV", "ExcludeIdle", "Mmap", "Comm",
		"Freq", "InheritStat", "EnableOnExec", "Task", "Watermark",
		"MmapData", "SampleIDAll", "ExcludeHost", "ExcludeGuest",
		"ExcludeCallchainKernel", "ExcludeCallchainUser", "Mmap2",
		"CommExec", "UseClockID", "ContextSwitch",
	}
	for _, name := range bitfieldNames {
		// Must be a pointer here to be able to use reflection to set
		// fields
		ea := &EventAttr{}
		reflect.ValueOf(ea).Elem().FieldByName(name).SetBool(true)
		writeBuffer := &bytes.Buffer{}
		err := ea.write(writeBuffer)
		assert(t, err == nil, "unexpected error for bitfield %s: %v", name, err)

		var actualAttr EventAttr
		readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
		err = actualAttr.read(readBuffer)
		assert(t, err == nil, "unexpected error for bitfield %s: %v", name, err)

		assert(t, reflect.DeepEqual(*ea, actualAttr),
			"bitfield %s not serialized properly\n\n\texp: %#v\n\n\tgot: %#v\n\n",
			name, ea, actualAttr)
	}
}

func TestEventHeaderRead(t *testing.T) {
	expectedHeader := eventHeader{
		Type: 827634,
		Misc: 23746,
		Size: 26734,
	}
	writeBuffer := &bytes.Buffer{}
	err := binary.Write(writeBuffer, binary.LittleEndian, expectedHeader)
	ok(t, err)

	var actualHeader eventHeader
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	err = actualHeader.read(readBuffer)
	ok(t, err)
	equals(t, expectedHeader, actualHeader)
}

func TestCommRecordRead(t *testing.T) {
	expectedRecord := CommRecord{
		Pid:  72463,
		Tid:  297843,
		Comm: []byte{'b', 'a', 's', 'h'},
	}
	writeBuffer := &bytes.Buffer{}
	err := binary.Write(writeBuffer, binary.LittleEndian, expectedRecord.Pid)
	ok(t, err)
	err = binary.Write(writeBuffer, binary.LittleEndian, expectedRecord.Tid)
	ok(t, err)
	_, err = writeBuffer.Write(expectedRecord.Comm)
	ok(t, err)
	padding := make([]byte, 8-len(expectedRecord.Comm))
	_, err = writeBuffer.Write(padding)
	ok(t, err)

	var actualRecord CommRecord
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	actualRecord.read(readBuffer)
	equals(t, expectedRecord, actualRecord)
}

func TestExitRecordRead(t *testing.T) {
	expectedRecord := ExitRecord{
		Pid:  28374,
		Ppid: 937845,
		Tid:  9248375,
		Ptid: 23487,
		Time: 2934685723958647,
	}
	writeBuffer := &bytes.Buffer{}
	err := binary.Write(writeBuffer, binary.LittleEndian, expectedRecord)
	ok(t, err)

	var actualRecord ExitRecord
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	actualRecord.read(readBuffer)
	equals(t, expectedRecord, actualRecord)
}

func TestLostRecordRead(t *testing.T) {
	expectedRecord := LostRecord{
		ID:   923784,
		Lost: 92837447,
	}
	writeBuffer := &bytes.Buffer{}
	err := binary.Write(writeBuffer, binary.LittleEndian, expectedRecord)
	ok(t, err)

	var actualRecord LostRecord
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	actualRecord.read(readBuffer)
	equals(t, expectedRecord, actualRecord)
}

func TestForkRecordRead(t *testing.T) {
	expectedRecord := ForkRecord{
		Pid:  97843,
		Ppid: 293847,
		Tid:  239487,
		Ptid: 203498,
		Time: 92837645928456,
	}
	writeBuffer := &bytes.Buffer{}
	err := binary.Write(writeBuffer, binary.LittleEndian, expectedRecord)
	ok(t, err)

	var actualRecord ForkRecord
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	actualRecord.read(readBuffer)
	equals(t, expectedRecord, actualRecord)
}

func (cg *CounterGroup) write(t *testing.T, writeBuffer io.Writer, format uint64) {
	if format&PERF_FORMAT_GROUP != 0 {
		err := binary.Write(writeBuffer, binary.LittleEndian, uint64(len(cg.Values)))
		ok(t, err)
		if format&PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
			err = binary.Write(writeBuffer, binary.LittleEndian, cg.TimeEnabled)
			ok(t, err)
		}
		if format&PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
			err = binary.Write(writeBuffer, binary.LittleEndian, cg.TimeRunning)
			ok(t, err)
		}
		for _, v := range cg.Values {
			err = binary.Write(writeBuffer, binary.LittleEndian, v.Value)
			ok(t, err)
			if format&PERF_FORMAT_ID != 0 {
				err = binary.Write(writeBuffer, binary.LittleEndian, v.ID)
				ok(t, err)
			}
		}
	} else {
		equals(t, 1, len(cg.Values)) // ensure the test is correct

		err := binary.Write(writeBuffer, binary.LittleEndian, cg.Values[0].Value)
		ok(t, err)
		if format&PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
			err = binary.Write(writeBuffer, binary.LittleEndian, cg.TimeEnabled)
			ok(t, err)
		}
		if format&PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
			err = binary.Write(writeBuffer, binary.LittleEndian, cg.TimeRunning)
			ok(t, err)
		}
		if format&PERF_FORMAT_ID != 0 {
			err = binary.Write(writeBuffer, binary.LittleEndian, cg.Values[0].ID)
			ok(t, err)
		}
	}
}

func TestCounterGroupRead(t *testing.T) {
	expectedGroup := CounterGroup{
		TimeEnabled: 98237645,
		TimeRunning: 20938745,
		Values: []CounterValue{
			CounterValue{
				ID:    92836457,
				Value: 923478,
			},
		},
	}

	format := PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID
	writeBuffer := &bytes.Buffer{}
	expectedGroup.write(t, writeBuffer, format)

	var actualGroup CounterGroup
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	actualGroup.read(readBuffer, format)
	equals(t, expectedGroup, actualGroup)

	format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID
	writeBuffer = &bytes.Buffer{}
	expectedGroup.write(t, writeBuffer, format)

	actualGroup = CounterGroup{}
	readBuffer = bytes.NewBuffer(writeBuffer.Bytes())
	actualGroup.read(readBuffer, format)
	equals(t, expectedGroup, actualGroup)
}

func (s *SampleRecord) write(t *testing.T, w io.Writer, attr EventAttr) {
	if attr.SampleType&PERF_SAMPLE_IDENTIFIER != 0 {
		err := binary.Write(w, binary.LittleEndian, s.SampleID)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_IP != 0 {
		err := binary.Write(w, binary.LittleEndian, s.IP)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_TID != 0 {
		err := binary.Write(w, binary.LittleEndian, s.Pid)
		ok(t, err)
		err = binary.Write(w, binary.LittleEndian, s.Tid)
	}
	if attr.SampleType&PERF_SAMPLE_TIME != 0 {
		err := binary.Write(w, binary.LittleEndian, s.Time)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_ADDR != 0 {
		err := binary.Write(w, binary.LittleEndian, s.Addr)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_ID != 0 {
		err := binary.Write(w, binary.LittleEndian, s.ID)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_STREAM_ID != 0 {
		err := binary.Write(w, binary.LittleEndian, s.StreamID)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_CPU != 0 {
		err := binary.Write(w, binary.LittleEndian, s.CPU)
		ok(t, err)
		err = binary.Write(w, binary.LittleEndian, uint32(0))
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_PERIOD != 0 {
		err := binary.Write(w, binary.LittleEndian, s.Period)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_READ != 0 {
		s.V.write(t, w, attr.ReadFormat)
	}
	if attr.SampleType&PERF_SAMPLE_CALLCHAIN != 0 {
		err := binary.Write(w, binary.LittleEndian, uint64(len(s.IPs)))
		ok(t, err)
		for _, ip := range s.IPs {
			err = binary.Write(w, binary.LittleEndian, ip)
			ok(t, err)
		}
	}
	if attr.SampleType&PERF_SAMPLE_RAW != 0 {
		err := binary.Write(w, binary.LittleEndian, uint32(len(s.RawData)))
		ok(t, err)
		_, err = w.Write(s.RawData)
		ok(t, err)
	}
	if attr.SampleType&PERF_SAMPLE_BRANCH_STACK != 0 {
		err := binary.Write(w, binary.LittleEndian, uint64(len(s.Branches)))
		ok(t, err)
		for _, b := range s.Branches {
			err = binary.Write(w, binary.LittleEndian, b.From)
			ok(t, err)
			err = binary.Write(w, binary.LittleEndian, b.To)
			ok(t, err)

			var flags uint64
			if b.Mispred {
				flags |= 1 << 0
			}
			if b.Predicted {
				flags |= 1 << 1
			}
			if b.InTx {
				flags |= 1 << 2
			}
			if b.Abort {
				flags |= 1 << 3
			}
			flags |= uint64(b.Cycles) << 4
			err = binary.Write(w, binary.LittleEndian, flags)
			ok(t, err)
		}
	}
}

func TestSampleRecordRead(t *testing.T) {
	expectedRecord := SampleRecord{
		SampleID: 0,        // PERF_SAMPLE_IDENTIFIER
		IP:       98276345, // PERF_SAMPLE_IP
		Pid:      237846,   // PERF_SAMPLE_TID
		Tid:      287346,
		Time:     23948576, // PERF_SAMPLE_TIME
		Addr:     9467805,  // PERF_SAMPLE_ADDR
		ID:       423,      // PERF_SAMPLE_ID
		StreamID: 3598,     // PERF_SAMPLE_STREAM_ID
		CPU:      2,        // PERF_SAMPLE_CPU
		Period:   876,      // PERF_SAMPLE_PERIOD

		// PERF_SAMPLE_READ
		V: CounterGroup{
			TimeEnabled: 297843,
			TimeRunning: 102983457,
			Values: []CounterValue{
				CounterValue{97854, 42837},
			},
		},

		// PERF_SAMPLE_CALLCHAIN
		IPs: []uint64{123, 456, 789},

		// PERF_SAMPLE_RAW
		RawData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},

		// PERF_SAMPLE_BRANCH_STACK
		Branches: []BranchEntry{
			BranchEntry{
				From:      243,
				To:        2341,
				Mispred:   false,
				Predicted: true,
				InTx:      false,
				Abort:     true,
				Cycles:    123,
			},
		},

		// Not Implemented:
		// PERF_SAMPLE_REGS_USER
		// PERF_SAMPLE_STACK_USER
		// PERF_SAMPLE_WEIGHT
		// PERF_SAMPLE_DATA_SRC
		// PERF_SAMPLE_TRANSACTION
		// PERF_SAMPLE_REGS_INTR
	}

	attr := EventAttr{}
	attr.SampleType = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
		PERF_SAMPLE_ADDR | PERF_SAMPLE_ID | PERF_SAMPLE_STREAM_ID |
		PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD |
		PERF_SAMPLE_READ | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_RAW |
		PERF_SAMPLE_BRANCH_STACK
	attr.ReadFormat = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
		PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING

	writeBuffer := &bytes.Buffer{}
	expectedRecord.write(t, writeBuffer, attr)

	var actualRecord SampleRecord
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	actualRecord.read(readBuffer, &attr)
	equals(t, expectedRecord, actualRecord)
}

func TestSampleIDGetSize(t *testing.T) {
	sampleTypes := map[uint64]int{
		PERF_SAMPLE_TID:        8,
		PERF_SAMPLE_TIME:       8,
		PERF_SAMPLE_ID:         8,
		PERF_SAMPLE_STREAM_ID:  8,
		PERF_SAMPLE_CPU:        8,
		PERF_SAMPLE_IDENTIFIER: 8,

		PERF_SAMPLE_TID | PERF_SAMPLE_TIME: 16,
		PERF_SAMPLE_ID | PERF_SAMPLE_CPU:   16,

		PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID:              24,
		PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_TID | PERF_SAMPLE_STREAM_ID: 24,

		PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU: 32,
	}
	sampleTypes[PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_ID|
		PERF_SAMPLE_STREAM_ID|PERF_SAMPLE_CPU|
		PERF_SAMPLE_IDENTIFIER] = 48

	wg := sync.WaitGroup{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			for x := 0; x < 100; x++ {
				s := SampleID{}
				for sampleType, expectedSize := range sampleTypes {
					size := s.getSize(sampleType, true)
					equals(t, expectedSize, size)
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func (sid *SampleID) write(t *testing.T, w io.Writer, sampleType uint64) {
	if sampleType&PERF_SAMPLE_TID != 0 {
		err := binary.Write(w, binary.LittleEndian, sid.PID)
		ok(t, err)
		err = binary.Write(w, binary.LittleEndian, sid.TID)
		ok(t, err)
	}
	if sampleType&PERF_SAMPLE_TIME != 0 {
		err := binary.Write(w, binary.LittleEndian, sid.Time)
		ok(t, err)
	}
	if sampleType&PERF_SAMPLE_ID != 0 {
		err := binary.Write(w, binary.LittleEndian, sid.ID)
		ok(t, err)
	}
	if sampleType&PERF_SAMPLE_STREAM_ID != 0 {
		err := binary.Write(w, binary.LittleEndian, sid.StreamID)
		ok(t, err)
	}
	if sampleType&PERF_SAMPLE_CPU != 0 {
		err := binary.Write(w, binary.LittleEndian, sid.CPU)
		ok(t, err)
		err = binary.Write(w, binary.LittleEndian, uint32(0))
		ok(t, err)
	}
	if sampleType&PERF_SAMPLE_IDENTIFIER != 0 {
		err := binary.Write(w, binary.LittleEndian, sid.ID)
		ok(t, err)
	}
}

func TestSampleIDRead(t *testing.T) {
	expectedSampleID := SampleID{
		PID:      987243,
		TID:      92387,
		Time:     23965,
		ID:       123,
		StreamID: 87456,
		CPU:      1,
	}
	sampleType := PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID |
		PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER

	writeBuffer := &bytes.Buffer{}
	expectedSampleID.write(t, writeBuffer, sampleType)

	var actualSampleID SampleID
	readBuffer := bytes.NewBuffer(writeBuffer.Bytes())
	actualSampleID.read(readBuffer, sampleType)
	equals(t, expectedSampleID, actualSampleID)
}

func TestSampleResolveEventAttr(t *testing.T) {
	expectedEventAttr := &EventAttr{
		SampleType:  PERF_SAMPLE_IDENTIFIER, // must be set
		SampleIDAll: true,                   // must be set
	}
	formatMap := map[uint64]*EventAttr{
		768435: expectedEventAttr,
	}
	expectedSampleID := uint64(768435)

	// 1. eventAttr is supplied non-nil for PERF_RECORD_SAMPLE
	sample := Sample{}
	sample.Type = PERF_RECORD_SAMPLE
	writeBuffer := &bytes.Buffer{}
	err := binary.Write(writeBuffer, binary.LittleEndian, expectedSampleID)
	ok(t, err)
	readBuffer := bytes.NewReader(writeBuffer.Bytes())
	actualSampleID, actualEventAttr :=
		sample.resolveEventAttr(readBuffer, 0, expectedEventAttr, nil)
	equals(t, expectedSampleID, actualSampleID)
	equals(t, expectedEventAttr, actualEventAttr)

	// 2. eventAttr is nil, sampleID is in formatMap for PERF_RECORD_SAMPLE
	readBuffer.Seek(0, os.SEEK_SET)
	actualSampleID, actualEventAttr =
		sample.resolveEventAttr(readBuffer, 0, nil, formatMap)
	equals(t, expectedSampleID, actualSampleID)
	equals(t, expectedEventAttr, actualEventAttr)

	// 3. eventAttr is supplied non-nil for !PERF_RECORD_SAMPLE
	sample = Sample{}
	sample.Type = PERF_RECORD_LOST
	sample.Size = 24
	writeBuffer = &bytes.Buffer{}
	err = binary.Write(writeBuffer, binary.LittleEndian, uint64(237456))
	ok(t, err)
	err = binary.Write(writeBuffer, binary.LittleEndian, uint64(238476))
	ok(t, err)
	err = binary.Write(writeBuffer, binary.LittleEndian, expectedSampleID)
	ok(t, err)
	readBuffer = bytes.NewReader(writeBuffer.Bytes())
	actualSampleID, actualEventAttr =
		sample.resolveEventAttr(readBuffer, 0, expectedEventAttr, nil)

	// 4. eventAttr is nil, sampleID is in formatMap for !PERF_RECORD_SAMPLE
	readBuffer.Seek(0, os.SEEK_SET)
	actualSampleID, actualEventAttr =
		sample.resolveEventAttr(readBuffer, 0, nil, formatMap)
	equals(t, expectedSampleID, actualSampleID)
	equals(t, expectedEventAttr, actualEventAttr)
}

func makeNonSampleRecord(
	t *testing.T,
	attr *EventAttr,
	typ uint32,
	i interface{},
	nbytes uint16,
) io.ReadSeeker {
	expectedSampleID := SampleID{
		PID:      987243,
		TID:      92387,
		Time:     23965,
		ID:       123,
		StreamID: 87456,
		CPU:      1,
	}

	size := nbytes + uint16(expectedSampleID.getSize(attr.SampleType, true))
	writeBuffer := &bytes.Buffer{}
	eh := eventHeader{typ, 0, size}
	err := binary.Write(writeBuffer, binary.LittleEndian, eh)
	ok(t, err)
	err = binary.Write(writeBuffer, binary.LittleEndian, i)
	ok(t, err)
	expectedSampleID.write(t, writeBuffer, attr.SampleType)

	return bytes.NewReader(writeBuffer.Bytes())
}

func makeSampleRecord(
	t *testing.T,
	attr *EventAttr,
	sr SampleRecord,
) io.ReadSeeker {
	writeBuffer := &bytes.Buffer{}
	eh := eventHeader{PERF_RECORD_SAMPLE, 0, 48}
	err := binary.Write(writeBuffer, binary.LittleEndian, eh)
	ok(t, err)
	sr.write(t, writeBuffer, *attr)

	return bytes.NewReader(writeBuffer.Bytes())
}

func TestSampleRead(t *testing.T) {
	attr := &EventAttr{
		SampleType: PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
			PERF_SAMPLE_ID | PERF_SAMPLE_STREAM_ID |
			PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER,
		SampleIDAll: true,
	}
	formatMap := map[uint64]*EventAttr{
		123: attr,
	}

	// PERF_RECORD_FORK
	fr := ForkRecord{
		Pid:  278634,
		Ppid: 827634,
		Tid:  93784,
		Ptid: 294387,
		Time: 2834765324,
	}
	r := makeNonSampleRecord(t, attr, PERF_RECORD_FORK, fr, sizeofForkRecord)
	sample := Sample{}
	err := sample.read(r, nil, formatMap)
	ok(t, err)
	equals(t, &fr, sample.Record)

	// PERF_RECORD_EXIT
	er := ExitRecord{
		Pid:  278634,
		Ppid: 827634,
		Tid:  93784,
		Ptid: 294387,
		Time: 2834765324,
	}
	r = makeNonSampleRecord(t, attr, PERF_RECORD_EXIT, er, sizeofExitRecord)
	sample = Sample{}
	err = sample.read(r, nil, formatMap)
	ok(t, err)
	equals(t, &er, sample.Record)

	// PERF_RECORD_LOST
	lr := LostRecord{
		ID:   872634,
		Lost: 283746,
	}
	r = makeNonSampleRecord(t, attr, PERF_RECORD_LOST, lr, sizeofLostRecord)
	sample = Sample{}
	err = sample.read(r, nil, formatMap)
	ok(t, err)
	equals(t, &lr, sample.Record)

	// PERF_RECORD_COMM
	cr := CommRecord{
		Pid:  72463,
		Tid:  297843,
		Comm: []byte{'b', 'a', 's', 'h'},
	}
	writeBuffer := &bytes.Buffer{}
	err = binary.Write(writeBuffer, binary.LittleEndian, cr.Pid)
	ok(t, err)
	err = binary.Write(writeBuffer, binary.LittleEndian, cr.Tid)
	ok(t, err)
	_, err = writeBuffer.Write(cr.Comm)
	ok(t, err)
	_, err = writeBuffer.Write(make([]byte, 4))
	ok(t, err)

	r = makeNonSampleRecord(t, attr, PERF_RECORD_COMM,
		writeBuffer.Bytes(), uint16(writeBuffer.Len()))
	sample = Sample{}
	err = sample.read(r, nil, formatMap)
	ok(t, err)
	equals(t, &cr, sample.Record)

	// PERF_RECORD_SAMPLE
	sr := SampleRecord{
		SampleID: 123,
		Pid:      287364,
		Tid:      297834,
		Time:     23487298347,
		ID:       123,
		StreamID: 123,
		CPU:      6,
	}
	r = makeSampleRecord(t, attr, sr)
	err = sample.read(r, attr, nil)
	ok(t, err)
	equals(t, &sr, sample.Record)

	// ... anything else, not valid-ish ...
	junk := []byte{1, 2, 3, 4, 5, 6, 7, 23, 4, 6}
	r = makeNonSampleRecord(t, attr, 283746, junk, uint16(len(junk)))
	sample = Sample{}
	err = sample.read(r, attr, formatMap)
	ok(t, err)
}
