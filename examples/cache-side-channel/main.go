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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/sensor"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/glog"

	"google.golang.org/genproto/googleapis/rpc/code"
)

const (
	// How many cache loads to sample on. After each sample period
	// of this many cache loads, the cache miss rate is calculated
	// and examined. This value tunes the trade-off between CPU
	// load and detection accuracy.
	llcLoadSampleSize = 10000

	// Alarm thresholds as cache miss rates (between 0 and 1).
	// These values tune the trade-off between false negatives and
	// false positives.
	alarmThresholdInfo    = 0.97
	alarmThresholdWarning = 0.98
	alarmThresholdError   = 0.99

	// perf_event_attr config value for LL cache loads
	perfConfigLLCLoads = perf.PERF_COUNT_HW_CACHE_LL |
		(perf.PERF_COUNT_HW_CACHE_OP_READ << 8) |
		(perf.PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16)

	// perf_event_attr config value for LL cache misses
	perfConfigLLCLoadMisses = perf.PERF_COUNT_HW_CACHE_LL |
		(perf.PERF_COUNT_HW_CACHE_OP_READ << 8) |
		(perf.PERF_COUNT_HW_CACHE_RESULT_MISS << 16)
)

type eventCounters struct {
	LLCLoads      uint64
	LLCLoadMisses uint64
}

func newSensor() *sensor.Sensor {
	s, err := sensor.NewSensor()
	if err != nil {
		glog.Fatalf("Could not create sensor: %s", err)
	}
	err = s.Start()
	if err != nil {
		glog.Fatalf("Could not start sensor: %s", err)
	}
	return s
}

type counterTracker struct {
	sensor   *sensor.Sensor
	counters []eventCounters
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	glog.Infof("Starting Capsule8 cache side channel detector")
	sensor := newSensor()
	ncpu := sensor.ProcFS.NumCPU()
	tracker := counterTracker{
		sensor:   sensor,
		counters: make([]eventCounters, ncpu),
	}

	// Create our subscription to read LL cache accesses and misses
	//
	// We ask the kernel to sample every llcLoadSampleSize LLC
	// loads. During each sample, the LLC load misses are also
	// recorded, as well as CPU number, PID/TID, and sample time.
	sub := &api.Subscription{
		EventFilter: &api.EventFilter{
			PerformanceEvents: []*api.PerformanceEventFilter{
				&api.PerformanceEventFilter{
					SampleRateType: api.SampleRateType_SAMPLE_RATE_TYPE_PERIOD,
					SampleRate: &api.PerformanceEventFilter_Period{
						Period: llcLoadSampleSize,
					},
					Events: []*api.PerformanceEventCounter{
						&api.PerformanceEventCounter{
							Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE,
							Config: perfConfigLLCLoads,
						},
						&api.PerformanceEventCounter{
							Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE,
							Config: perfConfigLLCLoadMisses,
						},
					},
				},
			},
		},
	}

	glog.Info("Monitoring for cache side channels")
	ctx, cancel := context.WithCancel(context.Background())
	status, err := sensor.NewSubscription(ctx, sub, tracker.dispatchEvent)
	if !(len(status) == 1 && status[0].Code == int32(code.Code_OK)) {
		for _, s := range status {
			glog.Infof("%s: %s", code.Code_name[s.Code], s.Message)
		}
	}
	if err != nil {
		glog.Fatalf("Could not register subscription: %v", err)
	}

	signals := make(chan os.Signal)
	signal.Notify(signals, os.Interrupt)
	<-signals
	close(signals)

	glog.Info("Shutting down gracefully")
	cancel()
	sensor.Stop()
}

func (t *counterTracker) dispatchEvent(e *api.TelemetryEvent) {
	event := e.Event.(*api.TelemetryEvent_Performance).Performance

	cpu := e.Cpu
	prevCounters := t.counters[cpu]
	t.counters[cpu] = eventCounters{}

	for _, v := range event.Values {
		switch v.Type {
		case api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE:
			switch v.Config {
			case perfConfigLLCLoads:
				t.counters[cpu].LLCLoads += v.Value
			case perfConfigLLCLoadMisses:
				t.counters[cpu].LLCLoadMisses += v.Value
			}
		}
	}

	counterDeltas := eventCounters{
		LLCLoads:      t.counters[cpu].LLCLoads - prevCounters.LLCLoads,
		LLCLoadMisses: t.counters[cpu].LLCLoadMisses - prevCounters.LLCLoadMisses,
	}

	t.alarm(e, counterDeltas)
}

func (t *counterTracker) alarm(
	event *api.TelemetryEvent,
	counters eventCounters,
) {
	LLCLoadMissRate := float32(counters.LLCLoadMisses) /
		float32(counters.LLCLoads)
	if LLCLoadMissRate <= alarmThresholdInfo {
		return
	}

	var fields []string
	fields = append(fields, fmt.Sprintf("LLCLoadMissRate=%v", LLCLoadMissRate))
	fields = append(fields, fmt.Sprintf("pid=%v", event.ProcessTgid))
	fields = append(fields, fmt.Sprintf("tid=%v", event.ProcessPid))
	fields = append(fields, fmt.Sprintf("cpu=%v", event.Cpu))
	if event.ContainerId != "" {
		fields = append(fields, fmt.Sprintf("container_name=%v", event.ContainerName))
		fields = append(fields, fmt.Sprintf("container_id=%v", event.ContainerId))
		fields = append(fields, fmt.Sprintf("container_image=%v", event.ImageName))
		fields = append(fields, fmt.Sprintf("container_image_id=%v", event.ImageId))
	}

	message := strings.Join(fields, " ")
	if LLCLoadMissRate > alarmThresholdError {
		glog.Errorf(message)
	} else if LLCLoadMissRate > alarmThresholdWarning {
		glog.Warningf(message)
	} else {
		glog.Infof(message)
	}
}
