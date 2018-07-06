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
	"fmt"
	"testing"
)

func TestParseTypeAndName(t *testing.T) {
	type testCase struct {
		s        string
		size     int
		isSigned bool

		dataType     int32
		dataTypeSize int
		dataLocSize  int
		arraySize    int
	}

	// These tests should return false, nil
	validTests := []testCase{
		testCase{"__data_loc char[] name", 4, true, TraceEventFieldTypeString, 1, 4, 0},
		testCase{"__data_loc long[] name", 4, true, TraceEventFieldTypeSignedInt64, 8, 4, 0},

		testCase{"short iii[4]", 8, true, TraceEventFieldTypeSignedInt16, 2, 0, 4},
		testCase{"short iii[NUM_PIDS]", 8, true, TraceEventFieldTypeSignedInt16, 2, 0, 4},
		testCase{"unknown_type x[8]", 32, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 8},

		testCase{"bool yesno", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"char x", 1, true, TraceEventFieldTypeSignedInt8, 1, 0, 0},
		testCase{"short x", 2, true, TraceEventFieldTypeSignedInt16, 2, 0, 0},
		testCase{"int x", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"long x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"long long x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"unsigned char x", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"unsigned short x", 2, false, TraceEventFieldTypeUnsignedInt16, 2, 0, 0},
		testCase{"unsigned int x", 4, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"unsigned long x", 8, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},
		testCase{"unsigned long long x", 8, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		testCase{"s8 x", 1, true, TraceEventFieldTypeSignedInt8, 1, 0, 0},
		testCase{"s16 x", 2, true, TraceEventFieldTypeSignedInt16, 2, 0, 0},
		testCase{"s32 x", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"s64 x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"u8 x", 1, true, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"u16 x", 2, true, TraceEventFieldTypeUnsignedInt16, 2, 0, 0},
		testCase{"u32 x", 4, true, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"u64 x", 8, true, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		testCase{"pid_t pid", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"const char *pointer", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"const char **pointer", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"enum color c", 4, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},

		testCase{"unknown_type x", 1, true, TraceEventFieldTypeSignedInt8, 1, 0, 0},
		testCase{"unknown_type x", 2, true, TraceEventFieldTypeSignedInt16, 2, 0, 0},
		testCase{"unknown_type x", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"unknown_type x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"unknown_type x", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"unknown_type x", 2, false, TraceEventFieldTypeUnsignedInt16, 2, 0, 0},
		testCase{"unknown_type x", 4, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"unknown_type x", 8, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		// For ints with kernel misrepresented sizes
		testCase{"int x", 16, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"unsigned int x", 16, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"long x", 16, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"unsigned long x", 16, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		// Misrepresented array sizes
		testCase{"u64 mismatch[6]", 24, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 3},
	}
	for _, tc := range validTests {
		field := traceEventField{
			Size:     tc.size,
			IsSigned: tc.isSigned,
		}
		skip, err := field.parseTypeAndName(tc.s)
		assert(t, err == nil, "unexpected error for %s", tc.s)
		assert(t, skip == false, "unexpected skip for %s", tc.s)

		assert(t, field.dataType == tc.dataType, "bad dataType for %s (got %d)", tc.s, field.dataType)
		assert(t, field.dataTypeSize == tc.dataTypeSize, "bad dataTypeSize for %s (got %d)", tc.s, field.dataTypeSize)
		assert(t, field.dataLocSize == tc.dataLocSize, "bad dataLocSize for %s (got %d)", tc.s, field.dataLocSize)
		assert(t, field.arraySize == tc.arraySize, "bad arraySize for %s (got %d)", tc.s, field.arraySize)
	}

	// These tests should return true, nil
	skipTests := []testCase{
		testCase{"__data_loc struct foo[] bar", 32, false, 0, 0, 0, 0},
		testCase{"struct foo bar", 32, false, 0, 0, 0, 0},
		testCase{"union foo bar", 8, false, 0, 0, 0, 0},
		testCase{"gid_t groups[NGROUP]", 64, true, 0, 0, 0, 0},
	}
	for _, tc := range skipTests {
		field := traceEventField{
			Size:     tc.size,
			IsSigned: tc.isSigned,
		}
		skip, err := field.parseTypeAndName(tc.s)
		assert(t, err == nil, "unexpected error for %s", tc.s)
		assert(t, skip == true, "unexpected no-skip for %s", tc.s)
	}

	// These tests should return an error
	invalidTests := []testCase{
		testCase{"__data_loc char name", 1, true, 0, 0, 0, 0},
		testCase{"char[] name", 1, true, 0, 0, 0, 0},
		testCase{"char [", 1, true, 0, 0, 0, 0},
		testCase{"bool", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
	}
	for _, tc := range invalidTests {
		field := traceEventField{
			Size:     tc.size,
			IsSigned: tc.isSigned,
		}
		_, err := field.parseTypeAndName(tc.s)
		assert(t, err != nil, "unexpected success %s", tc.s)
	}
}

func TestGetTraceEventFormat(t *testing.T) {
	var err error

	_, _, err = getTraceEventFormat("testdata", "nonexistent")
	assert(t, err != nil, "unexpected nil error result for non-existent file")

	invalidTests := []string{
		"id", "field", "offset", "size", "signed", "type",
	}
	for _, s := range invalidTests {
		name := fmt.Sprintf("invalid/invalid_%s", s)
		_, _, err = getTraceEventFormat("testdata", name)
		assert(t, err != nil, "unexpected nil error result for %s", name)
	}

	expectedFields := map[string]traceEventField{
		"common_flags": traceEventField{
			FieldName:    "common_flags",
			TypeName:     "unsigned char",
			Offset:       2,
			Size:         1,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt8,
			dataTypeSize: 1,
		},
		"common_pid": traceEventField{
			FieldName:    "common_pid",
			TypeName:     "int",
			Offset:       4,
			Size:         4,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeSignedInt32,
			dataTypeSize: 4,
		},
		"common_preempt_count": traceEventField{
			FieldName:    "common_preempt_count",
			TypeName:     "unsigned char",
			Offset:       3,
			Size:         1,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt8,
			dataTypeSize: 1,
		},
		"common_type": traceEventField{
			FieldName:    "common_type",
			TypeName:     "unsigned short",
			Offset:       0,
			Size:         2,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt16,
			dataTypeSize: 2,
		},
		"name": traceEventField{
			FieldName:    "name",
			TypeName:     "char",
			Offset:       8,
			Size:         4,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeString,
			dataTypeSize: 1,
			dataLocSize:  4,
		},
		"longs": traceEventField{
			FieldName:    "longs",
			TypeName:     "long",
			Offset:       12,
			Size:         4,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeSignedInt64,
			dataTypeSize: 8,
			dataLocSize:  4,
		},
		// Skips are turned into arrays of bytes
		"signed_skip": traceEventField{
			FieldName:    "signed_skip",
			TypeName:     "gid_t",
			Offset:       16,
			Size:         64,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeSignedInt8,
			dataTypeSize: 1,
			arraySize:    64,
		},
		"unsigned_skip": traceEventField{
			FieldName:    "unsigned_skip",
			TypeName:     "gid_t",
			Offset:       80,
			Size:         64,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt8,
			dataTypeSize: 1,
			arraySize:    64,
		},
	}

	id, actualFields, err := getTraceEventFormat("testdata", "valid/valid")
	ok(t, err)
	equals(t, uint16(31337), id)
	equals(t, expectedFields, actualFields)
}
