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

package sensor

import (
	"testing"

	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerDecoders(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	data := perf.TraceEventSampleData{
		"__container__": ContainerInfo{
			ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
			Name:       "capsule8-sensor-container",
			ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
			ImageName:  "capsule8-sensor-image",
			Pid:        872364,
			ExitCode:   255,
			Runtime:    ContainerRuntimeDocker,
			State:      ContainerStateRunning,
			JSONConfig: "This is the JSON config that isn't actually JSON",
			OCIConfig:  "This is the OCI config that isn't real",
		},
	}

	type testCase struct {
		decoder      perf.TraceEventDecoderFn
		expectedType interface{}
	}
	testCases := []testCase{
		testCase{
			decoder:      sensor.ContainerCache.decodeContainerCreatedEvent,
			expectedType: ContainerCreatedTelemetryEvent{},
		},
		testCase{
			decoder:      sensor.ContainerCache.decodeContainerDestroyedEvent,
			expectedType: ContainerDestroyedTelemetryEvent{},
		},
		testCase{
			decoder:      sensor.ContainerCache.decodeContainerExitedEvent,
			expectedType: ContainerExitedTelemetryEvent{},
		},
		testCase{
			decoder:      sensor.ContainerCache.decodeContainerRunningEvent,
			expectedType: ContainerRunningTelemetryEvent{},
		},
		testCase{
			decoder:      sensor.ContainerCache.decodeContainerUpdatedEvent,
			expectedType: ContainerUpdatedTelemetryEvent{},
		},
	}

	for _, tc := range testCases {
		i, err := tc.decoder(sample, data)
		require.NotNil(t, i)
		require.NoError(t, err)

		e, ok := i.(TelemetryEvent)
		require.True(t, ok)
		require.IsType(t, tc.expectedType, i)

		ok = testCommonTelemetryEventData(t, sensor, e)
		require.True(t, ok)

		cted := e.CommonTelemetryEventData()
		assert.Equal(t, data["__container__"], cted.Container)
	}
}

func TestFilterContainerId(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddContainerID("alice")
	cf.AddContainerID("bob")

	pass := ContainerInfo{
		ID: "alice",
	}
	assert.True(t, cf.Match(pass))

	fail := ContainerInfo{
		ID: "bill",
	}
	assert.False(t, cf.Match(fail))
}

func TestFilterContainerImageId(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddImageID("alice")
	cf.AddImageID("bob")

	pass := ContainerInfo{
		ID:      "pass",
		ImageID: "alice",
	}
	assert.True(t, cf.Match(pass))

	fail := ContainerInfo{
		ID:      "fail",
		ImageID: "bill",
	}
	assert.False(t, cf.Match(fail))
}

func TestFilterContainerImageNames(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddImageName("alice")
	cf.AddImageName("bob")

	pass := ContainerInfo{
		ID:        "pass",
		ImageName: "alice",
	}
	assert.True(t, cf.Match(pass))

	fail := ContainerInfo{
		ID:        "fail",
		ImageName: "bill",
	}
	assert.False(t, cf.Match(fail))
}

func TestFilterContainerNames(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddContainerName("alice")
	cf.AddContainerName("bob")

	pass := ContainerInfo{
		ID:   "pass",
		Name: "alice",
	}
	assert.True(t, cf.Match(pass))

	fail := ContainerInfo{
		ID:   "fail",
		Name: "bill",
	}
	assert.False(t, cf.Match(fail))
}
