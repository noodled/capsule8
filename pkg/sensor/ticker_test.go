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
	"context"
	"testing"
	"time"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeTickerEvent(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	sample := &perf.SampleRecord{}
	data := perf.TraceEventSampleData{
		"seconds":     int64(29345873297),
		"nanoseconds": int64(4569845689),
	}
	i, err := s.decodeTickerEvent(sample, data)
	require.NotNil(t, i)
	require.NoError(t, err)
	e, ok := i.(TickerTelemetryEvent)
	require.True(t, ok)

	ok = testCommonTelemetryEventData(t, sensor, e)
	require.True(t, ok)
	assert.Equal(t, data["seconds"], e.Seconds)
	assert.Equal(t, data["nanoseconds"], e.Nanoseconds)
}

func TestRegisterTickerEventFilter(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	// Sanity check
	assert.Len(t, s.status, 0)
	assert.Len(t, s.eventSinks, 0)

	// Invalid interval should fail
	s.RegisterTickerEventFilter(0, nil)
	assert.Len(t, s.status, 1)
	assert.Len(t, s.eventSinks, 0)

	// Invalid filter expression should fail
	e := expression.Equal(expression.Identifier("foo"), expression.Value("bar"))
	expr, err := expression.NewExpression(e)
	require.NotNil(t, expr)
	require.NoError(t, err)

	s.RegisterTickerEventFilter(50*int64(time.Millisecond), expr)
	assert.Len(t, s.status, 2)
	assert.Len(t, s.eventSinks, 0)

	// This should succeed
	s.RegisterTickerEventFilter(50*int64(time.Millisecond), nil)
	assert.Len(t, s.eventSinks, 1)

	ctx, cancel := context.WithCancel(context.Background())
	s.Run(ctx, nil)
	time.Sleep(200 * time.Millisecond)
	cancel()
}
