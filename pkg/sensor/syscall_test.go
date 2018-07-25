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

	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeDummySysEnter(t *testing.T) {
	// This does nothing except increase coverage since the function it's
	// "testing" does nothing except return nil, nil
	i, err := decodeDummySysEnter(nil, nil)
	assert.Nil(t, i)
	assert.NoError(t, err)
}

func TestDecodeSyscallTraceEnter(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	data := perf.TraceEventSampleData{
		"id":   int64(9237845),
		"arg0": uint64(0x11),
		"arg1": uint64(0x22),
		"arg2": uint64(0x33),
		"arg3": uint64(0x44),
		"arg4": uint64(0x55),
		"arg5": uint64(0x66),
	}
	i, err := s.decodeSyscallTraceEnter(sample, data)
	require.NotNil(t, i)
	require.NoError(t, err)
	e, ok := i.(SyscallEnterTelemetryEvent)
	require.True(t, ok)

	ok = testCommonTelemetryEventData(t, sensor, e)
	require.True(t, ok)
	assert.Equal(t, data["id"], e.ID)
	assert.Equal(t, data["arg0"], e.Arguments[0])
	assert.Equal(t, data["arg1"], e.Arguments[1])
	assert.Equal(t, data["arg2"], e.Arguments[2])
	assert.Equal(t, data["arg3"], e.Arguments[3])
	assert.Equal(t, data["arg4"], e.Arguments[4])
	assert.Equal(t, data["arg5"], e.Arguments[5])
}

func TestDecodeSysExit(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	data := perf.TraceEventSampleData{
		"id":  int64(9237845),
		"ret": int64(3824567),
	}
	i, err := s.decodeSysExit(sample, data)
	require.NotNil(t, i)
	require.NoError(t, err)
	e, ok := i.(SyscallExitTelemetryEvent)
	require.True(t, ok)

	ok = testCommonTelemetryEventData(t, sensor, e)
	require.True(t, ok)
	assert.Equal(t, data["id"], e.ID)
	assert.Equal(t, data["ret"], e.Return)
}
