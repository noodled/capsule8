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
	"reflect"
	"testing"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessDecoders(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	data := perf.TraceEventSampleData{
		"filename":          "/bin/bash",
		"exec_command_line": []string{"bash", "-l"},

		"code":             int32(234987),
		"exit_status":      uint32(495678),
		"exit_signal":      uint32(11),
		"exit_core_dumped": true,

		"fork_child_pid": int32(9485),
		"fork_child_id":  "some string that is a child process id",

		"cwd": "/var/run/capsule8",
	}

	type testCase struct {
		decoder      perf.TraceEventDecoderFn
		expectedType interface{}
		fieldChecks  map[string]string
	}
	testCases := []testCase{
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessExecEvent,
			expectedType: ProcessExecTelemetryEvent{},
			fieldChecks: map[string]string{
				"filename":          "Filename",
				"exec_command_line": "CommandLine",
			},
		},
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessExitEvent,
			expectedType: ProcessExitTelemetryEvent{},
			fieldChecks: map[string]string{
				"code":             "ExitCode",
				"exit_status":      "ExitStatus",
				"exit_signal":      "ExitSignal",
				"exit_core_dumped": "ExitCoreDumped",
			},
		},
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessForkEvent,
			expectedType: ProcessForkTelemetryEvent{},
			fieldChecks: map[string]string{
				"fork_child_pid": "ChildPID",
				"fork_child_id":  "ChildProcessID",
			},
		},
		testCase{
			decoder:      sensor.ProcessCache.decodeProcessUpdateEvent,
			expectedType: ProcessUpdateTelemetryEvent{},
			fieldChecks: map[string]string{
				"cwd": "CWD",
			},
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

		value := reflect.ValueOf(i)
		for k, v := range tc.fieldChecks {
			assert.Equal(t, data[k], value.FieldByName(v).Interface())
		}
	}
}

func TestProcessEventRegistration(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()

	e := expression.Equal(expression.Identifier("foo"), expression.Value("bar"))
	expr, err := expression.NewExpression(e)
	require.NotNil(t, expr)
	require.NoError(t, err)

	funcs := []func(*expression.Expression){
		s.RegisterProcessExecEventFilter,
		s.RegisterProcessExitEventFilter,
		s.RegisterProcessForkEventFilter,
		s.RegisterProcessUpdateEventFilter,
	}
	for i, f := range funcs {
		f(expr)
		assert.Len(t, s.status, i+1)
		assert.Len(t, s.eventSinks, i)

		f(nil)
		assert.Len(t, s.eventSinks, i+1)
	}
}
