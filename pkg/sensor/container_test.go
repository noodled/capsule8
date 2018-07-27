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

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"
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
		data["common_pid"] = int32(sensorPID)
		i, err := tc.decoder(sample, data)
		require.Nil(t, i)
		require.NoError(t, err)

		delete(data, "common_pid")
		i, err = tc.decoder(sample, data)
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

func TestContainerCache(t *testing.T) {
	const id = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"

	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	cache := sensor.ContainerCache

	// Lookup non-existant
	info := cache.LookupContainer(id, false)
	assert.Nil(t, info)

	// Lookup && create
	info = cache.LookupContainer(id, true)
	assert.NotNil(t, info)

	info2 := cache.LookupContainer(id, false)
	assert.Equal(t, info, info2)

	// Delete and verify
	sampleID := perf.SampleID{Time: uint64(sys.CurrentMonotonicRaw())}
	cache.DeleteContainer(id, ContainerRuntimeDocker, sampleID)

	info = cache.LookupContainer(id, false)
	assert.NotNil(t, info)

	cache.DeleteContainer(id, ContainerRuntimeUnknown, sampleID)

	info = cache.LookupContainer(id, false)
	assert.Nil(t, info)

	// Lookup && create again
	info = cache.LookupContainer(id, true)
	assert.NotNil(t, info)

	info2 = cache.LookupContainer(id, false)
	assert.Equal(t, info, info2)

	// Update
	changes := map[string]interface{}{
		"foo":   "this field does not exist",
		"State": ContainerStateExited,
	}
	sampleID.Time = uint64(sys.CurrentMonotonicRaw())
	info.Update(cache, ContainerRuntimeDocker, sampleID, changes)

	info = cache.LookupContainer(id, false)
	assert.Equal(t, ContainerRuntimeDocker, info.Runtime)
	assert.Equal(t, ContainerStateExited, info.State)

	changes = map[string]interface{}{
		"Name":     "capsule8-sensor",
		"Pid":      int(3874),
		"ExitCode": int(unix.SIGSEGV) | 0x80,
	}
	sampleID.Time = uint64(sys.CurrentMonotonicRaw())
	info.Update(cache, ContainerRuntimeDocker, sampleID, changes)

	assert.Equal(t, "capsule8-sensor", info.Name)
	assert.Equal(t, int(3874), info.Pid)
	assert.Equal(t, int(unix.SIGSEGV)|0x80, info.ExitCode)

	changes = map[string]interface{}{
		"State": ContainerStateRunning,
	}
	info.Update(cache, ContainerRuntimeUnknown, sampleID, changes)
	assert.Equal(t, ContainerStateExited, info.State)
}

func TestContainerEventRegistration(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()

	e := expression.Equal(expression.Identifier("foo"), expression.Value("bar"))
	expr, err := expression.NewExpression(e)
	require.NotNil(t, expr)
	require.NoError(t, err)

	funcs := []func(*expression.Expression){
		s.RegisterContainerCreatedEventFilter,
		s.RegisterContainerRunningEventFilter,
		s.RegisterContainerExitedEventFilter,
		s.RegisterContainerDestroyedEventFilter,
		s.RegisterContainerUpdatedEventFilter,
	}
	for i, f := range funcs {
		f(expr)
		assert.Len(t, s.status, i+1)
		assert.Len(t, s.eventSinks, i)

		f(nil)
		assert.Len(t, s.eventSinks, i+1)
	}
}

func TestContainerFilterLen(t *testing.T) {
	cf := ContainerFilter{}
	assert.Equal(t, 0, cf.Len())

	cf.AddContainerID("abc")
	assert.Equal(t, 1, cf.Len())

	cf.AddContainerName("abc")
	assert.Equal(t, 2, cf.Len())

	cf.AddImageID("abc")
	assert.Equal(t, 3, cf.Len())

	err := cf.AddImageName("*abc*")
	if assert.NoError(t, err) {
		assert.Equal(t, 4, cf.Len())
	}
	err = cf.AddImageName("*abc*")
	if assert.NoError(t, err) {
		assert.Equal(t, 4, cf.Len())
	}

	err = cf.AddImageName("*.[ch")
	assert.Error(t, err)
}

func TestContainerMatch(t *testing.T) {
	var cf *ContainerFilter
	info := ContainerInfo{}

	// A nil ContainerFilter should always match
	m := cf.Match(info)
	assert.True(t, m)

	// An empty ContainerInfo should never match
	cf = &ContainerFilter{}
	m = cf.Match(info)
	assert.False(t, m)
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
