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

	"github.com/capsule8/capsule8/pkg/expression"
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

		data["common_pid"] = int32(sensorPID)
		i, err := tc.decoder(sample, data)
		assert.Nil(t, i)
		assert.NoError(t, err)

		delete(data, "common_pid")
		i, err = tc.decoder(sample, data)
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

const networkKprobeFormat = `name: ^^NAME^^
ID: ^^ID^^
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int fd;	offset:8;	size:4;	signed:1;
	field:u16 sa_family;	offset:12;	size:2;	signed:0;
	field:u16 sin_port;	offset:14;	size:2;	signed:0;
	field:u32 sin_addr;	offset:16;	size:4;	signed:0;
	field:__data_loc char[] sun_path;	offset:20;	size:4;	signed:1;
	field:u16 sin6_port;	offset:22;	size:2;	signed:0;
	field:u64 sin6_addr_high;	offset:24;	size:8;	signed:0;
	field:u64 sin6_addr_low;	offset:32;	size:8;	signed:0;

print fmt: "fd=%d sa_family=%d sin_port=%d sin_addr=%d sun_path=\"%s\" sin6_port=%d sin6_addr_high=%d sin6_addr_low=%d", REC->fd, REC->sa_family, REC->sin_port, REC->sin_addr, __get_str(sun_path), REC->sin6_port, REC->sin6_addr_high, REC->sin6_addr_low`

func TestNetworkEventRegistration(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()

	e := expression.Equal(expression.Identifier("foo"), expression.Value("bar"))
	expr, err := expression.NewExpression(e)
	require.NotNil(t, expr)
	require.NoError(t, err)

	type testCase struct {
		name    string
		fn      func(*expression.Expression)
		kprobes []string
	}
	testCases := []testCase{
		testCase{"accept attempt", s.RegisterNetworkAcceptAttemptEventFilter, nil},
		testCase{"accept result", s.RegisterNetworkAcceptResultEventFilter, nil},
		testCase{"bind attempt", s.RegisterNetworkBindAttemptEventFilter, []string{networkKprobeFormat}},
		testCase{"bind result", s.RegisterNetworkBindResultEventFilter, nil},
		testCase{"connect attempt", s.RegisterNetworkConnectAttemptEventFilter, []string{networkKprobeFormat}},
		testCase{"connect result", s.RegisterNetworkConnectResultEventFilter, nil},
		testCase{"listen attempt", s.RegisterNetworkListenAttemptEventFilter, nil},
		testCase{"listen result", s.RegisterNetworkListenResultEventFilter, nil},
		testCase{"recvfrom attempt", s.RegisterNetworkRecvfromAttemptEventFilter, nil},
		testCase{"recvfrom result", s.RegisterNetworkRecvfromResultEventFilter, nil},
		testCase{"sendto attempt", s.RegisterNetworkSendtoAttemptEventFilter, []string{networkKprobeFormat, networkKprobeFormat}},
		testCase{"sendto result", s.RegisterNetworkSendtoResultEventFilter, nil},
	}
	for _, tc := range testCases {
		beforeStatus := len(s.status)
		beforeEventSinks := len(s.eventSinks)

		for _, f := range tc.kprobes {
			newUnitTestKprobe(t, sensor, f)
		}
		tc.fn(expr)
		assert.Condition(t, func() bool { return len(s.status) > beforeStatus }, tc.name)
		assert.Len(t, s.eventSinks, beforeEventSinks, tc.name)

		for _, f := range tc.kprobes {
			newUnitTestKprobe(t, sensor, f)
		}
		tc.fn(nil)
		assert.Condition(t, func() bool { return len(s.eventSinks) > beforeEventSinks }, tc.name, s.status)
	}
}
