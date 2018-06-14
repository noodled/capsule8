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
	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"
)

var fileOpenEventTypes = expression.FieldTypeMap{
	"filename": expression.ValueTypeString,
	"flags":    expression.ValueTypeSignedInt32,
	"mode":     expression.ValueTypeSignedInt32,
}

const (
	fsDoSysOpenKprobeAddress   = "do_sys_open"
	fsDoSysOpenKprobeFetchargs = "filename=+0(%si):string flags=%dx:s32 mode=%cx:s32"
)

func (s *Subscription) decodeDoSysOpen(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	ev := s.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	ev.Event = &api.TelemetryEvent_File{
		File: &api.FileEvent{
			Type:      api.FileEventType_FILE_EVENT_TYPE_OPEN,
			Filename:  data["filename"].(string),
			OpenFlags: data["flags"].(int32),
			OpenMode:  data["mode"].(int32),
		},
	}

	return ev, nil
}

// RegisterFileOpenEventFilter registers a file open event filter with a
// subscription.
func (s *Subscription) RegisterFileOpenEventFilter(filter *expression.Expression) {
	s.registerKprobe(fsDoSysOpenKprobeAddress, false,
		fsDoSysOpenKprobeFetchargs, s.decodeDoSysOpen,
		filter, fileOpenEventTypes)
}
