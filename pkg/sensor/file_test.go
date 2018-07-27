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
	"testing"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeDoSysOpen(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	data := perf.TraceEventSampleData{
		"common_pid": int32(sensorPID),
		"filename":   "/path/to/foo.bar",
		"flags":      int32(29384756),
		"mode":       int32(0664),
	}

	i, err := s.decodeDoSysOpen(sample, data)
	require.Nil(t, i)
	require.NoError(t, err)

	delete(data, "common_pid")
	i, err = s.decodeDoSysOpen(sample, data)
	require.NotNil(t, i)
	require.NoError(t, err)
	e, ok := i.(FileOpenTelemetryEvent)
	require.True(t, ok)

	ok = testCommonTelemetryEventData(t, sensor, e)
	require.True(t, ok)
	assert.Equal(t, data["filename"], e.Filename)
	assert.Equal(t, data["flags"], e.Flags)
	assert.Equal(t, data["mode"], e.Mode)
}

func TestRegisterFileOpenEventFilter(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	e := expression.Equal(expression.Identifier("foo"), expression.Value("bar"))
	expr, err := expression.NewExpression(e)
	require.NotNil(t, expr)
	require.NoError(t, err)

	format := `name: ^^NAME^^
id: ^^ID^^
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:__data_loc char[] filename;	offset:16;	size:4;	signed:1;
	field:s32 flags;	offset:20;	size:4;	signed:1;
	field:s32 mode;	offset:24;	size:4;	signed:1;

print fmt: "filename=\"%s\" flags=%d mode=%d", __get_str(filename), REC->flags, REC->mode`

	newUnitTestKprobe(t, sensor, format)
	s.RegisterFileOpenEventFilter(expr)
	assert.Len(t, s.status, 1)
	assert.Len(t, s.eventSinks, 0)

	newUnitTestKprobe(t, sensor, format)
	s.RegisterFileOpenEventFilter(nil)
	assert.Len(t, s.eventSinks, 1)
}
