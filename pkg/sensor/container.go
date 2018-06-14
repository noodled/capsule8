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
	"reflect"
	"sync"
	"unicode"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/gobwas/glob"
	"github.com/golang/glog"

	"golang.org/x/sys/unix"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var containerEventTypes = expression.FieldTypeMap{
	"name":             expression.ValueTypeString,
	"image_id":         expression.ValueTypeString,
	"image_name":       expression.ValueTypeString,
	"host_pid":         expression.ValueTypeSignedInt32,
	"exit_code":        expression.ValueTypeSignedInt32,
	"exit_status":      expression.ValueTypeUnsignedInt32,
	"exit_signal":      expression.ValueTypeUnsignedInt32,
	"exit_core_dumped": expression.ValueTypeBool,
}

// ContainerCache is a cache of container information
type ContainerCache struct {
	sync.Mutex
	cache map[string]*ContainerInfo

	sensor *Sensor

	// These are external event IDs registered with the sensor's event
	// monitor instance. The cache will enqueue these events as appropriate
	// as the cache is updated.
	ContainerCreatedEventID   uint64
	ContainerRunningEventID   uint64
	ContainerExitedEventID    uint64
	ContainerDestroyedEventID uint64
	ContainerUpdatedEventID   uint64
}

// ContainerState represents the state of a container (created, running, etc.)
type ContainerState uint

const (
	// ContainerStateUnknown indicates that the container is in an unknown
	// state.
	ContainerStateUnknown ContainerState = iota

	// ContainerStateCreated indicates the container exists, but is not
	// running.
	ContainerStateCreated

	// ContainerStatePaused indicates the container is paused.
	ContainerStatePaused

	// ContainerStateRunning indicates the container is running.
	ContainerStateRunning

	// ContainerStateRestarting indicates the container is in the process
	// of restarting.
	ContainerStateRestarting

	// ContainerStateExited indicates the container has exited.
	ContainerStateExited

	// ContainerStateRemoving indicates the container is being removed.
	ContainerStateRemoving
)

// ContainerStateNames is a mapping of container states to printable names.
var ContainerStateNames = map[ContainerState]string{
	ContainerStateCreated:    "created",
	ContainerStateRestarting: "restarting",
	ContainerStateRunning:    "running",
	ContainerStateRemoving:   "removing",
	ContainerStatePaused:     "paused",
	ContainerStateExited:     "exited",
}

// ContainerRuntime represents the runtime used to manager a container
type ContainerRuntime uint

const (
	// ContainerRuntimeUnknown means the container runtime managing the
	// container is unknown. Information about the container comes from
	// runc, the kernel, or other generic sources.
	ContainerRuntimeUnknown ContainerRuntime = iota

	// ContainerRuntimeDocker means the container is managed by Docker.
	ContainerRuntimeDocker
)

// ContainerInfo records interesting information known about a container.
type ContainerInfo struct {
	cache *ContainerCache // the cache to which this info belongs

	ID        string
	Name      string
	ImageID   string
	ImageName string

	Pid      int
	ExitCode int

	Runtime ContainerRuntime
	State   ContainerState

	JSONConfig string
	OCIConfig  string
}

// NewContainerCache creates a new container cache.
func NewContainerCache(sensor *Sensor) *ContainerCache {
	cache := &ContainerCache{
		cache:  make(map[string]*ContainerInfo),
		sensor: sensor,
	}

	var err error
	cache.ContainerCreatedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_CREATED", cache.decodeContainerCreatedEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerRunningEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_RUNNING", cache.decodeContainerRunningEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerExitedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_EXITED", cache.decodeContainerExitedEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerDestroyedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_DESTROYED", cache.decodeContainerDestroyedEvent)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerUpdatedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_UPDATED", cache.decodeContainerUpdatedEvent)
	if err != nil {
		glog.Fatalf("Failed to register extern event: %s", err)
	}

	return cache
}

// DeleteContainer removes a container from the cache.
func (cc *ContainerCache) DeleteContainer(
	containerID string,
	runtime ContainerRuntime,
	sampleID perf.SampleID,
) {
	cc.Lock()
	info, ok := cc.cache[containerID]
	if ok {
		if runtime == info.Runtime {
			delete(cc.cache, containerID)
		} else {
			ok = false
		}
	}
	cc.Unlock()

	if ok {
		glog.V(2).Infof("Sending CONTAINER_DESTROYED for %s", info.ID)
		cc.enqueueContainerEvent(cc.ContainerDestroyedEventID,
			sampleID, info)
	}
}

func (cc *ContainerCache) newContainerInfo(containerID string) *ContainerInfo {
	return &ContainerInfo{
		cache:   cc,
		ID:      containerID,
		Runtime: ContainerRuntimeUnknown,
	}
}

// LookupContainer searches the cache for a container by ID and returns any
// information found, optionally creating a cache entry if there is one does
// not already exist.
func (cc *ContainerCache) LookupContainer(containerID string, create bool) *ContainerInfo {
	cc.Lock()
	defer cc.Unlock()

	info := cc.cache[containerID]
	if info == nil && create {
		info = cc.newContainerInfo(containerID)
		cc.cache[containerID] = info
	}

	return info
}

func (cc *ContainerCache) enqueueContainerEvent(
	eventID uint64,
	sampleID perf.SampleID,
	info *ContainerInfo,
) error {
	ws := unix.WaitStatus(info.ExitCode)
	data := map[string]interface{}{
		"container_id":     info.ID,
		"name":             info.Name,
		"image_id":         info.ImageID,
		"image_name":       info.ImageName,
		"host_pid":         int32(info.Pid),
		"exit_code":        int32(info.ExitCode),
		"exit_status":      uint32(0),
		"exit_signal":      uint32(0),
		"exit_core_dumped": ws.CoreDump(),
	}

	if ws.Exited() {
		data["exit_status"] = uint32(ws.ExitStatus())
	}
	if ws.Signaled() {
		data["exit_signal"] = uint32(ws.Signal())
	}

	return cc.sensor.Monitor.EnqueueExternalSample(eventID, sampleID, data)
}

func (cc *ContainerCache) newContainerEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
	eventType api.ContainerEventType,
) (*api.TelemetryEvent, error) {
	event := cc.sensor.NewEventFromSample(sample, data)
	if event == nil {
		return nil, nil
	}

	cev := &api.ContainerEvent{
		Type:           eventType,
		ImageId:        data["image_id"].(string),
		ImageName:      data["image_name"].(string),
		HostPid:        data["host_pid"].(int32),
		ExitCode:       data["exit_code"].(int32),
		ExitStatus:     data["exit_status"].(uint32),
		ExitSignal:     data["exit_signal"].(uint32),
		ExitCoreDumped: data["exit_core_dumped"].(bool),
	}

	if s, ok := data["docker_config"].(string); ok && len(s) > 0 {
		cev.DockerConfigJson = s
	}
	if s, ok := data["oci_config"].(string); ok && len(s) > 0 {
		cev.OciConfigJson = s
	}

	event.ContainerId = data["container_id"].(string)
	event.Event = &api.TelemetryEvent_Container{
		Container: cev,
	}
	return event, nil
}

func (cc *ContainerCache) decodeContainerCreatedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED)
}

func (cc *ContainerCache) decodeContainerRunningEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING)
}

func (cc *ContainerCache) decodeContainerExitedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED)
}

func (cc *ContainerCache) decodeContainerDestroyedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED)
}

func (cc *ContainerCache) decodeContainerUpdatedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED)
}

// Update updates the data cached for a container with new information. Some
// new information may trigger telemetry events to fire.
func (info *ContainerInfo) Update(
	runtime ContainerRuntime,
	sampleID perf.SampleID,
	data map[string]interface{},
) {
	if info.Runtime == ContainerRuntimeUnknown {
		info.Runtime = runtime
	}

	oldState := info.State
	dataChanged := false

	s := reflect.ValueOf(info).Elem()
	t := s.Type()
	for i := t.NumField() - 1; i >= 0; i-- {
		f := t.Field(i)
		if !unicode.IsUpper(rune(f.Name[0])) {
			continue
		}
		v, ok := data[f.Name]
		if !ok {
			continue
		}
		if !reflect.TypeOf(v).AssignableTo(f.Type) {
			glog.Fatalf("Cannot assign %v to %s %s",
				v, f.Name, f.Type)
		}

		if s.Field(i).Interface() != v {
			if f.Name != "State" {
				dataChanged = true
			} else if info.Runtime != runtime {
				// Only allow state changes from the runtime
				// known to be managing the container.
				continue
			}
			s.Field(i).Set(reflect.ValueOf(v))
		}
	}

	if info.State != oldState {
		if oldState < ContainerStateCreated {
			glog.V(2).Infof("Sending CONTAINER_CREATED for %s", info.ID)
			info.cache.enqueueContainerEvent(
				info.cache.ContainerCreatedEventID, sampleID,
				info)
		}
		if oldState < ContainerStateRunning &&
			info.State >= ContainerStateRunning {
			glog.V(2).Infof("Sending CONTAINER_RUNNING for %s", info.ID)
			info.cache.enqueueContainerEvent(
				info.cache.ContainerRunningEventID, sampleID,
				info)
		}
		if oldState < ContainerStateRestarting &&
			info.State >= ContainerStateRestarting {
			glog.V(2).Infof("Sending CONTAINER_EXITED for %s", info.ID)
			info.cache.enqueueContainerEvent(
				info.cache.ContainerExitedEventID,
				sampleID, info)
		}
	} else if dataChanged {
		glog.V(2).Infof("Sending CONTAINER_UPDATED for %s", info.ID)
		info.cache.enqueueContainerEvent(
			info.cache.ContainerUpdatedEventID, sampleID, info)
	}
}

func (s *Subscription) registerContainerEventFilter(
	eventID uint64,
	full bool,
	expr *expression.Expression,
) {
	if es, err := s.addEventSink(eventID, expr, containerEventTypes); err != nil {
		s.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Invalid container filter expression: %v", err))
	} else if full {
		es.containerView = api.ContainerEventView_FULL
	} else {
		es.containerView = api.ContainerEventView_BASIC
	}
}

// RegisterContainerCreatedEventFilter registers a container created event
// filter with a subscription.
func (s *Subscription) RegisterContainerCreatedEventFilter(full bool, expr *expression.Expression) {
	s.registerContainerEventFilter(
		s.sensor.ContainerCache.ContainerCreatedEventID,
		full, expr)
}

// RegisterContainerRunningEventFilter registers a container running event
// filter with a subscription.
func (s *Subscription) RegisterContainerRunningEventFilter(full bool, expr *expression.Expression) {
	s.registerContainerEventFilter(
		s.sensor.ContainerCache.ContainerRunningEventID,
		full, expr)
}

// RegisterContainerExitedEventFilter registers a container exited event
// filter with a subscription.
func (s *Subscription) RegisterContainerExitedEventFilter(full bool, expr *expression.Expression) {
	s.registerContainerEventFilter(
		s.sensor.ContainerCache.ContainerExitedEventID,
		full, expr)
}

// RegisterContainerDestroyedEventFilter registers a container destroyed event
// filter with a subscription.
func (s *Subscription) RegisterContainerDestroyedEventFilter(full bool, expr *expression.Expression) {
	s.registerContainerEventFilter(
		s.sensor.ContainerCache.ContainerDestroyedEventID,
		full, expr)
}

// RegisterContainerUpdatedEventFilter registers a container updated event
// filter with a subscription.
func (s *Subscription) RegisterContainerUpdatedEventFilter(full bool, expr *expression.Expression) {
	s.registerContainerEventFilter(
		s.sensor.ContainerCache.ContainerUpdatedEventID,
		full, expr)
}

///////////////////////////////////////////////////////////////////////////////

// NewContainerFilter creates a new container filter
func NewContainerFilter() *ContainerFilter {
	return &ContainerFilter{}
}

// ContainerFilter is a filter that is used to filter telemetry events based
// on container ID, container name, image ID, or image name.
type ContainerFilter struct {
	containerIDs   map[string]struct{}
	containerNames map[string]struct{}
	imageIDs       map[string]struct{}
	imageGlobs     map[string]glob.Glob
}

// Len returns the number of filters that are active within a ContainerFilter.
func (c *ContainerFilter) Len() int {
	return len(c.containerIDs) + len(c.containerNames) +
		len(c.imageIDs) + len(c.imageGlobs)
}

// AddContainerID adds a container ID to a container filter.
func (c *ContainerFilter) AddContainerID(cid string) {
	if len(cid) > 0 {
		if c.containerIDs == nil {
			c.containerIDs = make(map[string]struct{})
		}
		c.containerIDs[cid] = struct{}{}
	}
}

// AddContainerName adds a container name to a container filter.
func (c *ContainerFilter) AddContainerName(cname string) {
	if len(cname) > 0 {
		if c.containerNames == nil {
			c.containerNames = make(map[string]struct{})
		}
		c.containerNames[cname] = struct{}{}
	}
}

// AddImageID adds an image ID to a container filter.
func (c *ContainerFilter) AddImageID(iid string) {
	if len(iid) > 0 {
		if c.imageIDs == nil {
			c.imageIDs = make(map[string]struct{})
		}
		c.imageIDs[iid] = struct{}{}
	}
}

// AddImageName adds and image name to a container filter.
func (c *ContainerFilter) AddImageName(iname string) error {
	if len(iname) > 0 {
		if c.imageGlobs == nil {
			c.imageGlobs = make(map[string]glob.Glob)
		} else if _, ok := c.imageGlobs[iname]; ok {
			return nil
		}
		if g, err := glob.Compile(iname, '/'); err == nil {
			c.imageGlobs[iname] = g
		} else {
			return err
		}
	}
	return nil
}

// match evaluates the container filter for an event and determines whether the
// event matches the criteria set forth by the filter.
func (c *ContainerFilter) match(e *api.TelemetryEvent) bool {
	// Fast path: Check if containerId is in containerIds map
	if _, ok := c.containerIDs[e.ContainerId]; ok {
		return true
	}

	// Slow path: Check if other identifiers are in maps. If they are, add
	// the containerId to containerIds map to take fast path next time.
	switch ev := e.Event.(type) {
	case *api.TelemetryEvent_Container:
		cev := ev.Container
		if _, ok := c.containerNames[cev.Name]; ok {
			c.AddContainerID(e.ContainerId)
			return true
		}

		if _, ok := c.imageIDs[cev.ImageId]; ok {
			c.AddContainerID(e.ContainerId)
			return true
		}

		if c.imageGlobs != nil && cev.ImageName != "" {
			for _, g := range c.imageGlobs {
				if g.Match(cev.ImageName) {
					c.AddContainerID(e.ContainerId)
					return true
				}
			}
		}
	}

	return false
}
