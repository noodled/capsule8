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

package perf

import (
	"reflect"
	"sync"
	"testing"
)

func TestNewTraceEventDecoder(t *testing.T) {
	var err error

	// This should error -- testdata does not have this event
	_, _, err = newTraceEventDecoder("testdata", "task/task_newtask", nil)
	assert(t, err != nil, "Expected error result")

	_, _, err = newTraceEventDecoder("testdata", "invalid/invalid_id", nil)
	assert(t, err != nil, "Expected error result")

	decoder, id, err := newTraceEventDecoder("testdata", "valid/valid", nil)
	ok(t, err)
	equals(t, uint16(31337), id)
	assert(t, decoder != nil, "Expected non-nil decoder")
}

func TestDecodeDataType(t *testing.T) {
	type testCase struct {
		dataType      int32
		rawData       []byte
		expectedValue interface{}
		expectedErr   bool
	}
	testCases := []testCase{
		testCase{
			dataType:      TraceEventFieldTypeString,
			rawData:       nil,
			expectedValue: nil,
			expectedErr:   true,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt8,
			rawData:       []byte{8},
			expectedValue: int8(8),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt16,
			rawData:       []byte{0x34, 0x12},
			expectedValue: int16(0x1234),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt32,
			rawData:       []byte{0x11, 0x22, 0x33, 0x44},
			expectedValue: int32(0x44332211),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt64,
			rawData:       []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11},
			expectedValue: int64(0x1122334455667788),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt8,
			rawData:       []byte{0x56},
			expectedValue: uint8(0x56),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt16,
			rawData:       []byte{0x34, 0x12},
			expectedValue: uint16(0x1234),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt32,
			rawData:       []byte{0x11, 0x22, 0x33, 0x44},
			expectedValue: uint32(0x44332211),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt64,
			rawData:       []byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89},
			expectedValue: uint64(0x8978675645342312),
			expectedErr:   false,
		},
		testCase{
			dataType:      29384756,
			rawData:       nil,
			expectedValue: nil,
			expectedErr:   true,
		},
	}
	for _, tc := range testCases {
		actualValue, err := decodeDataType(tc.dataType, tc.rawData)
		if tc.expectedErr {
			assert(t, err != nil, "expected error for dataType %d", tc.dataType)
		} else {
			assert(t, err == nil, "unexpected error for dataType %d", tc.dataType)
		}
		assert(t, reflect.DeepEqual(tc.expectedValue, actualValue),
			"Result does not match for dataType %d\n\n\texp: %#v\n\n\tgot: %#v",
			tc.dataType, tc.expectedValue, actualValue)
	}
}

func TestDecodeRawData(t *testing.T) {
	rawData := []byte{
		0x1c, 0x00, 0x06, 0x00, // name4
		0x22, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, // name8
		0x11, 0x22, 0x33, 0x44, // pid
		0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, // args
		0x28, 0x00, 0x04, 0x00, // foo

		'N', 'A', 'M', 'E', '4', 0,
		'N', 'A', 'M', 'E', '8', 0,
		0x11, 0x22, 0x33, 0x44,
	}

	d := traceEventDecoder{
		fields: map[string]traceEventField{
			"name4": traceEventField{
				FieldName:    "name4",
				Offset:       0,
				dataType:     TraceEventFieldTypeString,
				dataTypeSize: 1,
				dataLocSize:  4,
			},
			"name8": traceEventField{
				FieldName:    "name8",
				Offset:       4,
				dataType:     TraceEventFieldTypeString,
				dataTypeSize: 1,
				dataLocSize:  8,
			},
			"pid": traceEventField{
				FieldName: "pid",
				Offset:    12,
				dataType:  TraceEventFieldTypeSignedInt32,
			},
			"args": traceEventField{
				FieldName:    "args",
				Offset:       16,
				dataType:     TraceEventFieldTypeUnsignedInt32,
				dataTypeSize: 4,
				arraySize:    2,
			},
			"foo": traceEventField{
				FieldName:    "foo",
				Offset:       24,
				dataType:     TraceEventFieldTypeUnsignedInt8,
				dataTypeSize: 1,
				dataLocSize:  4,
			},
		},
	}

	e := TraceEventSampleData{
		"name4": "NAME4",
		"name8": "NAME8",
		"pid":   int32(0x44332211),
		"args":  []interface{}{uint32(0x01010101), uint32(0x02020202)},
		"foo":   []interface{}{uint8(0x11), uint8(0x22), uint8(0x33), uint8(0x44)},
	}

	data, err := d.decodeRawData(rawData)
	ok(t, err)
	equals(t, e, data)

	d = traceEventDecoder{
		fields: map[string]traceEventField{
			"error": traceEventField{
				FieldName:   "error",
				dataLocSize: 16,
			},
		},
	}
	_, err = d.decodeRawData(rawData)
	assert(t, err != nil, "Expected error")

	d = traceEventDecoder{
		fields: map[string]traceEventField{
			"error": traceEventField{
				FieldName: "error",
				dataType:  TraceEventFieldTypeString,
			},
		},
	}
	_, err = d.decodeRawData(rawData)
	assert(t, err != nil, "Expected error")

	d = traceEventDecoder{
		fields: map[string]traceEventField{
			"error": traceEventField{
				FieldName: "error",
				dataType:  TraceEventFieldTypeString,
				arraySize: 4,
			},
		},
	}
	_, err = d.decodeRawData(rawData)
	assert(t, err != nil, "Expected error")
}

func TestTraceEventDecoderMap(t *testing.T) {
	dm := newTraceEventDecoderMap("testdata")
	assert(t, dm != nil, "newTraceEventDecoderMap returned nil")
	equals(t, 0, dm.getDecoderMap().Len())
	equals(t, (*traceEventDecoder)(nil), dm.getDecoder(8888))

	dm.removeDecoderInPlace("valid/valid")
	equals(t, 0, dm.getDecoderMap().Len())

	dm.RemoveDecoder("valid/valid")
	equals(t, 0, dm.getDecoderMap().Len())

	dm = newTraceEventDecoderMap("testdata")
	id, err := dm.addDecoderInPlace("valid/valid", nil)
	ok(t, err)
	equals(t, 1, dm.getDecoderMap().Len())
	equals(t, uint16(31337), id)

	id, err = dm.AddDecoder("valid/valid2", nil)
	ok(t, err)
	equals(t, 2, dm.getDecoderMap().Len())
	equals(t, uint16(78), id)

	_, err = dm.addDecoderInPlace("invalid/invalid_id", nil)
	assert(t, err != nil, "Expected error")

	_, err = dm.AddDecoder("invalid/invalid_field", nil)
	assert(t, err != nil, "Expected error")

	dm.removeDecoderInPlace("valid/valid")
	equals(t, 1, dm.getDecoderMap().Len())

	id, err = dm.AddDecoder("valid/valid", nil)
	ok(t, err)
	equals(t, 2, dm.getDecoderMap().Len())
	equals(t, uint16(31337), id)

	dm.RemoveDecoder("valid/valid")
	equals(t, 1, dm.getDecoderMap().Len())

	// This just tests to ensure concurrent access does not panic
	dm = newTraceEventDecoderMap("testdata")
	wg := sync.WaitGroup{}
	for i := uint64(0); i < 8; i++ {
		wg.Add(1)
		go func(i uint64) {
			for x := uint64(0); x < 1000; x++ {
				switch x % 6 {
				case 0:
					dm.AddDecoder("valid/valid", nil)
				case 1:
					dm.getDecoder(31337)
				case 2:
					dm.RemoveDecoder("valid/valid")
				case 3:
					dm.RemoveDecoder("valid/does_not_exist")
				case 4:
					dm.AddDecoder("valid/valid2", nil)
				case 5:
					dm.RemoveDecoder("valid/valid2")
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestDecodeSample(t *testing.T) {
	dm := newTraceEventDecoderMap("testdata")
	id, err := dm.addDecoderInPlace("valid/valid2",
		func(sample *SampleRecord, data TraceEventSampleData) (interface{}, error) {
			return "hello, world", nil
		})
	ok(t, err)
	equals(t, uint16(78), id)

	rawData := []byte{
		0x4e, 0x00, // common_type
		0x88,                   // common_flags
		0x23,                   // common_preempt_count
		0x11, 0x22, 0x33, 0x44, // common_pid
		0x44, 0x33, 0x22, 0x11, // pid
	}

	exp := TraceEventSampleData{
		"common_type":          uint16(78),
		"common_flags":         uint8(0x88),
		"common_preempt_count": uint8(0x23),
		"common_pid":           int32(0x44332211),
		"pid":                  int32(0x11223344),
	}

	s := &SampleRecord{RawData: rawData}
	data, got, err := dm.DecodeSample(s)
	ok(t, err)
	equals(t, "hello, world", got)
	equals(t, exp, data)

	rawData = []byte{
		0x88, 0x88, // common_type
		0x88,                   // common_flags
		0x88,                   // common_preempt_count
		0x88, 0x88, 0x88, 0x88, // common_pid
	}
	s = &SampleRecord{RawData: rawData}
	data, got, err = dm.DecodeSample(s)
	ok(t, err)
	equals(t, TraceEventSampleData(nil), data)
	equals(t, nil, got)
}
