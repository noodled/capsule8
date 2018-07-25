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
	"reflect"
	"testing"

	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"
)

func TestNetworkDecoders(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	sample := &perf.SampleRecord{
		Time: uint64(sys.CurrentMonotonicRaw()),
	}
	data := perf.TraceEventSampleData{
		"fd":             uint64(258675234),
		"ret":            int64(8927364),
		"backlog":        uint64(24576),
		"sin_addr":       uint32(0x7f000001),
		"sin_port":       uint16(0x1f90),
		"sin6_addr_high": uint64(0x1122334455667788),
		"sin6_addr_low":  uint64(0x9900aabbccddeeff),
		"sin6_port":      uint16(0x8080),
		"sun_path":       "/path/to/local.socket",
	}
	families := []uint16{unix.AF_INET, unix.AF_INET6, unix.AF_LOCAL}

	type testCase struct {
		decoder      perf.TraceEventDecoderFn
		expectedType interface{}
		fieldChecks  map[string]string
	}
	testCases := []testCase{
		testCase{
			decoder:      s.decodeSysEnterAccept,
			expectedType: NetworkAcceptAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd": "FD",
			},
		},
		testCase{
			decoder:      s.decodeSysExitAccept,
			expectedType: NetworkAcceptResultTelemetryEvent{},
			fieldChecks: map[string]string{
				"ret": "Return",
			},
		},
		// 3x bind to catch all three address families
		testCase{
			decoder:      s.decodeSysBind,
			expectedType: NetworkBindAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysBind,
			expectedType: NetworkBindAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysBind,
			expectedType: NetworkBindAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysExitBind,
			expectedType: NetworkBindResultTelemetryEvent{},
			fieldChecks: map[string]string{
				"ret": "Return",
			},
		},
		// 3x connect to catch all three address families
		testCase{
			decoder:      s.decodeSysConnect,
			expectedType: NetworkConnectAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysConnect,
			expectedType: NetworkConnectAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysConnect,
			expectedType: NetworkConnectAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysExitConnect,
			expectedType: NetworkConnectResultTelemetryEvent{},
			fieldChecks: map[string]string{
				"ret": "Return",
			},
		},
		testCase{
			decoder:      s.decodeSysEnterListen,
			expectedType: NetworkListenAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":      "FD",
				"backlog": "Backlog",
			},
		},
		testCase{
			decoder:      s.decodeSysExitListen,
			expectedType: NetworkListenResultTelemetryEvent{},
			fieldChecks: map[string]string{
				"ret": "Return",
			},
		},
		testCase{
			decoder:      s.decodeSysEnterRecvfrom,
			expectedType: NetworkRecvfromAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd": "FD",
			},
		},
		testCase{
			decoder:      s.decodeSysExitRecvfrom,
			expectedType: NetworkRecvfromResultTelemetryEvent{},
			fieldChecks: map[string]string{
				"ret": "Return",
			},
		},

		// 3x sendto to catch all three address families
		testCase{
			decoder:      s.decodeSysSendto,
			expectedType: NetworkSendtoAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysSendto,
			expectedType: NetworkSendtoAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysSendto,
			expectedType: NetworkSendtoAttemptTelemetryEvent{},
			fieldChecks: map[string]string{
				"fd":        "FD",
				"sa_family": "Family",
			},
		},
		testCase{
			decoder:      s.decodeSysExitSendto,
			expectedType: NetworkSendtoResultTelemetryEvent{},
			fieldChecks: map[string]string{
				"ret": "Return",
			},
		},
	}

	for x, tc := range testCases {
		data["sa_family"] = families[x%len(families)]

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
		if _, ok := tc.fieldChecks["sa_family"]; ok {
			switch data["sa_family"] {
			case unix.AF_INET:
				assert.Equal(t, data["sin_addr"], value.FieldByName("IPv4Address").Interface())
				assert.Equal(t, data["sin_port"], value.FieldByName("IPv4Port").Interface())
			case unix.AF_INET6:
				assert.Equal(t, data["sin6_addr_high"], value.FieldByName("IPv6AddressHigh").Interface())
				assert.Equal(t, data["sin6_addr_low"], value.FieldByName("IPv6AddressLow").Interface())
				assert.Equal(t, data["sin6_port"], value.FieldByName("IPv6Port").Interface())
			case unix.AF_LOCAL:
				assert.Equal(t, data["sun_path"], value.FieldByName("UnixPath").Interface())
			}
		}
	}
}
