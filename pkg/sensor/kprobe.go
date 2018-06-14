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
	"fmt"
	"regexp"
	"strings"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var validSymbolRegex = regexp.MustCompile("^[A-Za-z_]{1}[\\w]*$")

func (s *Subscription) decodeKprobe(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	ev := s.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	args := make(map[string]*api.KernelFunctionCallEvent_FieldValue)
	for k, v := range data {
		value := &api.KernelFunctionCallEvent_FieldValue{}
		switch v := v.(type) {
		case []byte:
			value.FieldType = api.KernelFunctionCallEvent_BYTES
			value.Value = &api.KernelFunctionCallEvent_FieldValue_BytesValue{BytesValue: v}
		case string:
			value.FieldType = api.KernelFunctionCallEvent_STRING
			value.Value = &api.KernelFunctionCallEvent_FieldValue_StringValue{StringValue: v}
		case int8:
			value.FieldType = api.KernelFunctionCallEvent_SINT8
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: int64(v)}
		case int16:
			value.FieldType = api.KernelFunctionCallEvent_SINT16
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: int64(v)}
		case int32:
			value.FieldType = api.KernelFunctionCallEvent_SINT32
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: int64(v)}
		case int64:
			value.FieldType = api.KernelFunctionCallEvent_SINT64
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: v}
		case uint8:
			value.FieldType = api.KernelFunctionCallEvent_UINT8
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: uint64(v)}
		case uint16:
			value.FieldType = api.KernelFunctionCallEvent_UINT16
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: uint64(v)}
		case uint32:
			value.FieldType = api.KernelFunctionCallEvent_UINT32
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: uint64(v)}
		case uint64:
			value.FieldType = api.KernelFunctionCallEvent_UINT64
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: v}
		}
		args[k] = value
	}

	ev.Event = &api.TelemetryEvent_KernelCall{
		KernelCall: &api.KernelFunctionCallEvent{
			Arguments: args,
		},
	}

	return ev, nil
}

// RegisterKernelFunctionCallEventFilter registers a kernel function call event
// filter with a subscription.
func (s *Subscription) RegisterKernelFunctionCallEventFilter(
	symbol string,
	onReturn bool,
	arguments map[string]string,
	filter *expression.Expression,
) {
	// The symbol must begin with [A-Za-z_] and contain only [A-Za-z0-9_]
	// We do not accept addresses or offsets
	if !validSymbolRegex.MatchString(symbol) {
		s.logStatus(
			code.Code_INVALID_ARGUMENT,
			fmt.Sprintf("Kernel function call symbol %q is invalid", symbol))
		return
	}

	l := make([]string, 0, len(arguments))
	for k, v := range arguments {
		l = append(l, fmt.Sprintf("%s=%s", k, v))
	}
	fetchargs := strings.Join(l, " ")

	// Pass nil for filterTypes here to force the filter types to be
	// determined dynamically after the kprobe is registered with the
	// kernel.
	s.registerKprobe(symbol, onReturn, fetchargs, s.decodeKprobe,
		filter, nil)
}
