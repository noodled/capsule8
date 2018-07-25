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

func TestDecodePerfCounterEvent(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	counters := []perf.CounterEventValue{
		perf.CounterEventValue{
			EventType: perf.EventTypeHardware,
			Config:    239478,
			Value:     19823452,
		},
		perf.CounterEventValue{
			EventType: perf.EventTypeHardwareCache,
			Config:    984567,
			Value:     5678398457,
		},
		perf.CounterEventValue{
			EventType: perf.EventTypeSoftware,
			Config:    398457,
			Value:     7867568,
		},
	}

	i, err := s.decodePerfCounterEvent(sample, counters, 293847, 2340978)
	require.NotNil(t, i)
	require.NoError(t, err)
	e, ok := i.(PerformanceTelemetryEvent)
	require.True(t, ok)

	ok = testCommonTelemetryEventData(t, sensor, e)
	require.True(t, ok)
	assert.Equal(t, uint64(293847), e.TotalTimeEnabled)
	assert.Equal(t, uint64(2340978), e.TotalTimeRunning)
	assert.Equal(t, counters, e.Counters)
}
