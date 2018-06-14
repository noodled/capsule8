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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	api "github.com/capsule8/capsule8/api/v0"
	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/glog"

	"golang.org/x/sys/unix"

	"google.golang.org/genproto/googleapis/rpc/code"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TelemetryServiceGetEventsRequestFunc is a function called when a new
// subscription is requested.
type TelemetryServiceGetEventsRequestFunc func(
	request *api.GetEventsRequest,
)

// TelemetryServiceGetEventsResponseFunc is a function called when a new
// subscscription is processed. The response will be included or an error if
// there was an error processing the subscription.
type TelemetryServiceGetEventsResponseFunc func(
	response *api.GetEventsResponse,
	err error,
)

// TelemetryServiceStartFunc is a function called when the sensor service is
// started.
type TelemetryServiceStartFunc func()

// TelemetryServiceStopFunc is a function called when the sensor service is
// stopped.
type TelemetryServiceStopFunc func()

type telemetryServiceOptions struct {
	start             TelemetryServiceStartFunc
	stop              TelemetryServiceStopFunc
	getEventsRequest  TelemetryServiceGetEventsRequestFunc
	getEventsResponse TelemetryServiceGetEventsResponseFunc
}

// TelemetryServiceOption is used to implement optional arguments for
// NewTelemetryService. It must be exported, but it is not typically used
// directly.
type TelemetryServiceOption func(*telemetryServiceOptions)

// WithStartFunc specifies a function to be called when a telemetry service is
// started.
func WithStartFunc(f TelemetryServiceStartFunc) TelemetryServiceOption {
	return func(o *telemetryServiceOptions) {
		o.start = f
	}
}

// WithStopFunc specifies a function to be called when a telemetry service is
// stopped.
func WithStopFunc(f TelemetryServiceStopFunc) TelemetryServiceOption {
	return func(o *telemetryServiceOptions) {
		o.stop = f
	}
}

// WithGetEventsRequestFunc specifies a function to be called when a telemetry
// service GetEvents request has been received. It is called with the request.
func WithGetEventsRequestFunc(f TelemetryServiceGetEventsRequestFunc) TelemetryServiceOption {
	return func(o *telemetryServiceOptions) {
		o.getEventsRequest = f
	}
}

// WithGetEventsResponseFunc sepecifies a function to be called when a telemtry
// service GetEvents request has been processed. It is called with either the
// response or an error.
func WithGetEventsResponseFunc(f TelemetryServiceGetEventsResponseFunc) TelemetryServiceOption {
	return func(o *telemetryServiceOptions) {
		o.getEventsResponse = f
	}
}

// TelemetryService is a service that can be used with the ServiceManager to
// process telemetry subscription requests and stream the resulting telemetry
// events.
type TelemetryService struct {
	server *grpc.Server
	sensor *Sensor

	address string

	options telemetryServiceOptions
}

// NewTelemetryService creates a new TelemetryService instance that can be used
// with a ServiceManager instance.
func NewTelemetryService(
	sensor *Sensor,
	address string,
	options ...TelemetryServiceOption,
) *TelemetryService {
	ts := &TelemetryService{
		sensor:  sensor,
		address: address,
	}

	for _, o := range options {
		o(&ts.options)
	}

	return ts
}

// Name returns the human-readable name of the TelemetryService.
func (ts *TelemetryService) Name() string {
	return "gRPC Telemetry Server"
}

// Serve is the main entrypoint for the TelemetryService. It is normally called
// by the ServiceManager. It will service requests indefinitely from the calling
// Goroutine.
func (ts *TelemetryService) Serve() error {
	var (
		err error
		lis net.Listener
	)

	glog.V(1).Info("Serving gRPC API on ", ts.address)

	parts := strings.Split(ts.address, ":")
	if len(parts) > 1 && parts[0] == "unix" {
		socketPath := parts[1]

		// Check whether socket already exists and if someone
		// is already listening on it.
		_, err = os.Stat(socketPath)
		if err == nil {
			var ua *net.UnixAddr

			ua, err = net.ResolveUnixAddr("unix", socketPath)
			if err == nil {
				var c *net.UnixConn

				c, err = net.DialUnix("unix", nil, ua)
				if err == nil {
					// There is another running service.
					// Try to listen below and return the
					// error.
					c.Close()
				} else {
					// Remove the stale socket so the
					// listen below will succeed.
					os.Remove(socketPath)
				}
			}
		}

		oldMask := unix.Umask(0077)
		lis, err = net.Listen("unix", socketPath)
		unix.Umask(oldMask)
	} else {
		lis, err = net.Listen("tcp", ts.address)
	}

	if err != nil {
		return err
	}
	defer lis.Close()

	// Start local gRPC service on listener
	if config.Sensor.UseTLS {
		glog.V(1).Infoln("Starting telemetry server with TLS credentials")

		certificate, err := tls.LoadX509KeyPair(config.Sensor.TLSServerCertPath, config.Sensor.TLSServerKeyPath)
		if err != nil {
			return fmt.Errorf("could not load server key pair: %s", err)
		}

		certPool := x509.NewCertPool()
		ca, err := ioutil.ReadFile(config.Sensor.TLSCACertPath)
		if err != nil {
			return fmt.Errorf("could not read ca certificate: %s", err)
		}

		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return errors.New("failed to append certs")
		}

		creds := credentials.NewTLS(&tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{certificate},
			ClientCAs:    certPool,
		})
		ts.server = grpc.NewServer(grpc.Creds(creds))
	} else {
		glog.V(1).Infoln("Starting telemetry server")
		ts.server = grpc.NewServer()
	}

	t := &telemetryServiceServer{
		sensor:  ts.sensor,
		service: ts,
	}
	api.RegisterTelemetryServiceServer(ts.server, t)

	if ts.options.start != nil {
		ts.options.start()
	}

	return ts.server.Serve(lis)
}

// Stop will stop a running TelemetryService.
func (ts *TelemetryService) Stop() {
	ts.server.Stop()
	if ts.options.stop != nil {
		ts.options.stop()
	}
}

type telemetryServiceServer struct {
	sensor  *Sensor
	service *TelemetryService
}

func (t *telemetryServiceServer) getEventsError(err error) error {
	if t.service.options.getEventsResponse != nil {
		t.service.options.getEventsResponse(nil, err)
	}
	return err
}

func (t *telemetryServiceServer) GetEvents(
	req *api.GetEventsRequest,
	stream api.TelemetryService_GetEventsServer,
) error {
	if t.service.options.getEventsRequest != nil {
		t.service.options.getEventsRequest(req)
	}

	sub := req.Subscription
	glog.V(1).Infof("GetEvents(%+v)", sub)

	if sub.EventFilter == nil {
		glog.V(1).Infof("Invalid subscription: %+v", sub)
		return t.getEventsError(errors.New("Invalid subscription (no EventFilter)"))
	}

	// Validate sub.Modifier
	var (
		err              error
		maxEvents        int64
		throttleDuration time.Duration
	)
	if sub.Modifier != nil {
		if sub.Modifier.Limit != nil {
			maxEvents = sub.Modifier.Limit.Limit
			if maxEvents < 1 {
				err = fmt.Errorf("LimitModifier is invalid (%d)",
					maxEvents)
				return t.getEventsError(err)
			}
		}
		if sub.Modifier.Throttle != nil {
			if sub.Modifier.Throttle.Interval <= 0 {
				err = fmt.Errorf("ThrottleModifier interval is invalid (%d)",
					sub.Modifier.Throttle.Interval)
				return t.getEventsError(err)
			}
			throttleDuration =
				time.Duration(sub.Modifier.Throttle.Interval)
			switch sub.Modifier.Throttle.IntervalType {
			case api.ThrottleModifier_MILLISECOND:
				throttleDuration *= time.Millisecond
			case api.ThrottleModifier_SECOND:
				throttleDuration *= time.Second
			case api.ThrottleModifier_MINUTE:
				throttleDuration *= time.Minute
			case api.ThrottleModifier_HOUR:
				throttleDuration *= time.Hour
			default:
				err = fmt.Errorf("ThrottleModifier interval type is invalid (%d)",
					sub.Modifier.Throttle.IntervalType)
				return t.getEventsError(err)
			}
		}
	}

	events := make(chan *api.TelemetryEvent,
		config.Sensor.ChannelBufferLength)
	f := func(e *api.TelemetryEvent) {
		// Send the event to the data channel, but drop the event if
		// the channel is full. Do not block the sensor from delivering
		// telemetry to other subscribers.
		select {
		case events <- e:
		default:
		}
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	r := &api.GetEventsResponse{}
	subscr := t.sensor.NewSubscription()

	if sub.ContainerFilter != nil {
		cf := NewContainerFilter()
		for _, id := range sub.ContainerFilter.Ids {
			cf.AddContainerID(id)
		}
		for _, name := range sub.ContainerFilter.Names {
			cf.AddContainerName(name)
		}
		for _, id := range sub.ContainerFilter.ImageIds {
			cf.AddImageID(id)
		}
		for _, name := range sub.ContainerFilter.ImageNames {
			cf.AddImageName(name)
		}
		if cf.Len() > 0 {
			subscr.SetContainerFilter(cf)
		}
	}

	subscr.registerChargenEvents(sub.EventFilter.ChargenEvents)
	subscr.registerContainerEvents(sub.EventFilter.ContainerEvents)
	subscr.registerFileEvents(sub.EventFilter.FileEvents)
	subscr.registerKernelFunctionCallEvents(sub.EventFilter.KernelEvents)
	subscr.registerNetworkEvents(sub.EventFilter.NetworkEvents)
	subscr.registerPerformanceEvents(sub.EventFilter.PerformanceEvents)
	subscr.registerProcessEvents(sub.EventFilter.ProcessEvents)
	subscr.registerSyscallEvents(sub.EventFilter.SyscallEvents)
	subscr.registerTickerEvents(sub.EventFilter.TickerEvents)

	if r.Statuses, err = subscr.Run(ctx, f); err != nil {
		glog.Errorf("Failed to get events for subscription %+v: %v",
			sub, err)
		return t.getEventsError(err)
	}
	if err = stream.Send(r); err != nil {
		return t.getEventsError(err)
	}
	if t.service.options.getEventsResponse != nil {
		t.service.options.getEventsResponse(r, nil)
	}

	var nEvents int64
	nextEventTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			glog.V(1).Infof("Client disconnected, closing stream")
			return ctx.Err()
		case e := <-events:
			if throttleDuration != 0 {
				now := time.Now()
				if now.Before(nextEventTime) {
					break
				}
				nextEventTime = now
				nextEventTime.Add(throttleDuration)
			}
			r = &api.GetEventsResponse{
				Events: []*api.ReceivedTelemetryEvent{
					&api.ReceivedTelemetryEvent{Event: e},
				},
			}
			if err = stream.Send(r); err != nil {
				return err
			}
			if maxEvents > 0 {
				nEvents++
				if nEvents == maxEvents {
					return fmt.Errorf("Event limit reached (%d)",
						maxEvents)
				}
			}
		}
	}

	// unreachable
	return nil
}

func (s *Subscription) registerChargenEvents(events []*api.ChargenEventFilter) {
	for _, e := range events {
		s.RegisterChargenEventFilter(e.Length, nil)
	}
}

func (s *Subscription) registerContainerEvents(events []*api.ContainerEventFilter) {
	type registerFunc func(bool, *expression.Expression)

	var (
		filters       [6]*api.Expression
		subscriptions [6]registerFunc
		views         [6]bool
		wildcards     [6]bool
	)

	for _, e := range events {
		t := e.GetType()
		if t < 1 || t > 5 {
			s.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("ContainerEventType %d is invalid", t))
			continue
		}

		if subscriptions[t] == nil {
			switch t {
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED:
				subscriptions[t] = s.RegisterContainerCreatedEventFilter
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING:
				subscriptions[t] = s.RegisterContainerRunningEventFilter
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED:
				subscriptions[t] = s.RegisterContainerExitedEventFilter
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED:
				subscriptions[t] = s.RegisterContainerDestroyedEventFilter
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED:
				subscriptions[t] = s.RegisterContainerUpdatedEventFilter
			}
		}
		if e.View == api.ContainerEventView_FULL {
			views[t] = true
		}
		if e.FilterExpression == nil {
			wildcards[t] = true
			filters[t] = nil
		} else if !wildcards[t] {
			filters[t] = expression.LogicalOr(
				e.FilterExpression,
				filters[t])
		}
	}

	for i, f := range subscriptions {
		if f == nil {
			continue
		}
		if wildcards[i] {
			f(views[i], nil)
		} else if expr, err := expression.NewExpression(filters[i]); err == nil {
			f(views[i], expr)
		} else {
			s.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Invalid container filter expression: %v", err))
		}
	}
}

func rewriteFileEventFilter(fef *api.FileEventFilter) {
	if fef.Filename != nil {
		newExpr := expression.Equal(
			expression.Identifier("filename"),
			expression.Value(fef.Filename.Value))
		fef.FilterExpression = expression.LogicalAnd(
			newExpr, fef.FilterExpression)
		fef.Filename = nil
		fef.FilenamePattern = nil
	} else if fef.FilenamePattern != nil {
		newExpr := expression.Like(
			expression.Identifier("filename"),
			expression.Value(fef.FilenamePattern.Value))
		fef.FilterExpression = expression.LogicalAnd(
			newExpr, fef.FilterExpression)
		fef.FilenamePattern = nil
	}

	if fef.OpenFlagsMask != nil {
		newExpr := expression.BitwiseAnd(
			expression.Identifier("flags"),
			expression.Value(fef.OpenFlagsMask.Value))
		fef.FilterExpression = expression.LogicalAnd(
			newExpr, fef.FilterExpression)
		fef.OpenFlagsMask = nil
	}

	if fef.CreateModeMask != nil {
		newExpr := expression.BitwiseAnd(
			expression.Identifier("mode"),
			expression.Value(fef.CreateModeMask.Value))
		fef.FilterExpression = expression.LogicalAnd(
			newExpr, fef.FilterExpression)
		fef.CreateModeMask = nil
	}
}

func (s *Subscription) registerFileEvents(events []*api.FileEventFilter) {
	var (
		filter   *api.Expression
		wildcard bool
	)

	for _, e := range events {
		if e.Type != api.FileEventType_FILE_EVENT_TYPE_OPEN {
			s.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("FileEventType %d is invalid", e.Type))
			continue
		}

		// Translate deprecated fields into an expression
		rewriteFileEventFilter(e)

		if e.FilterExpression == nil {
			wildcard = true
			filter = nil
		} else if !wildcard {
			filter = expression.LogicalOr(filter, e.FilterExpression)
		}
	}

	if wildcard {
		s.RegisterFileOpenEventFilter(nil)
	} else if filter == nil {
		return
	} else if expr, err := expression.NewExpression(filter); err == nil {
		s.RegisterFileOpenEventFilter(expr)
	} else {
		s.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Invalid filter expression for file open filter: %v", err))
	}
}

func (s *Subscription) registerKernelFunctionCallEvents(events []*api.KernelFunctionCallFilter) {
	for _, e := range events {
		var onReturn bool
		switch e.Type {
		case api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_ENTER:
			onReturn = false
		case api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_EXIT:
			onReturn = true
		default:
			s.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("KernelFunctionCallEventType %d is invalid", e.Type))
			continue
		}

		var filterExpression *expression.Expression
		if expr := e.GetFilterExpression(); expr != nil {
			var err error
			filterExpression, err = expression.NewExpression(expr)
			if err != nil {
				s.logStatus(
					code.Code_UNKNOWN,
					fmt.Sprintf("Invalid filter expression for kernel function call filter: %v", err))
				continue
			}
		}

		s.RegisterKernelFunctionCallEventFilter(e.Symbol, onReturn,
			e.Arguments, filterExpression)
	}
}

type networkFilterItem struct {
	filter   *api.Expression
	wildcard bool
}

func (nfi *networkFilterItem) add(nef *api.NetworkEventFilter) {
	if nef.FilterExpression == nil {
		nfi.wildcard = true
		nfi.filter = nil
	} else if nfi.wildcard == false {
		nfi.filter = expression.LogicalOr(nef.FilterExpression,
			nfi.filter)
	}
}

type networkFilterItemRegisterFunc func(*expression.Expression)

func (nfi *networkFilterItem) register(
	s *Subscription,
	f networkFilterItemRegisterFunc,
) {
	if nfi != nil {
		if nfi.wildcard {
			f(nil)
		} else if nfi.filter != nil {
			if expr, err := expression.NewExpression(nfi.filter); err != nil {
				s.logStatus(
					code.Code_UNKNOWN,
					fmt.Sprintf("Invalid filter expression for network accept attempt filter: %v", err))
			} else {
				f(expr)
			}
		}
	}
}

type networkFilterSet struct {
	acceptAttemptFilters   networkFilterItem
	acceptResultFilters    networkFilterItem
	bindAttemptFilters     networkFilterItem
	bindResultFilters      networkFilterItem
	connectAttemptFilters  networkFilterItem
	connectResultFilters   networkFilterItem
	listenAttemptFilters   networkFilterItem
	listenResultFilters    networkFilterItem
	recvfromAttemptFilters networkFilterItem
	recvfromResultFilters  networkFilterItem
	sendtoAttemptFilters   networkFilterItem
	sendtoResultFilters    networkFilterItem
}

func (nfs *networkFilterSet) add(
	subscr *Subscription,
	nef *api.NetworkEventFilter,
) {
	switch nef.Type {
	case api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_ATTEMPT:
		nfs.acceptAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_RESULT:
		nfs.acceptResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_ATTEMPT:
		nfs.bindAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_RESULT:
		nfs.bindResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_ATTEMPT:
		nfs.connectAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_RESULT:
		nfs.connectResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT:
		nfs.listenAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_RESULT:
		nfs.listenResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_ATTEMPT:
		nfs.recvfromAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_RESULT:
		nfs.recvfromResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_ATTEMPT:
		nfs.sendtoAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_RESULT:
		nfs.sendtoResultFilters.add(nef)
	default:
		subscr.logStatus(
			code.Code_INVALID_ARGUMENT,
			fmt.Sprintf("Invalid NetworkEventType %d", nef.Type))
	}
}

func (s *Subscription) registerNetworkEvents(events []*api.NetworkEventFilter) {
	nfs := networkFilterSet{}
	for _, nef := range events {
		nfs.add(s, nef)
	}

	nfs.acceptAttemptFilters.register(s, s.RegisterNetworkAcceptAttemptEventFilter)
	nfs.acceptResultFilters.register(s, s.RegisterNetworkAcceptResultEventFilter)

	nfs.bindAttemptFilters.register(s, s.RegisterNetworkBindAttemptEventFilter)
	nfs.bindResultFilters.register(s, s.RegisterNetworkBindResultEventFilter)
	nfs.connectAttemptFilters.register(s, s.RegisterNetworkConnectAttemptEventFilter)
	nfs.connectResultFilters.register(s, s.RegisterNetworkConnectResultEventFilter)
	nfs.listenAttemptFilters.register(s, s.RegisterNetworkListenAttemptEventFilter)
	nfs.listenResultFilters.register(s, s.RegisterNetworkListenResultEventFilter)
	nfs.recvfromAttemptFilters.register(s, s.RegisterNetworkRecvfromAttemptEventFilter)
	nfs.recvfromResultFilters.register(s, s.RegisterNetworkRecvfromResultEventFilter)
	nfs.sendtoAttemptFilters.register(s, s.RegisterNetworkSendtoAttemptEventFilter)
	nfs.sendtoResultFilters.register(s, s.RegisterNetworkSendtoResultEventFilter)
}

func (s *Subscription) registerPerformanceEvents(events []*api.PerformanceEventFilter) {
	for _, e := range events {
		attr := perf.EventAttr{
			SampleType: perf.PERF_SAMPLE_CPU | perf.PERF_SAMPLE_RAW,
		}
		switch e.SampleRateType {
		case api.SampleRateType_SAMPLE_RATE_TYPE_PERIOD:
			if rate, ok := e.SampleRate.(*api.PerformanceEventFilter_Period); !ok {
				s.logStatus(
					code.Code_INVALID_ARGUMENT,
					fmt.Sprintf("Period not properly specified for periodic sample rate"))
				continue
			} else {
				attr.SamplePeriod = rate.Period
				attr.Freq = false
			}
		case api.SampleRateType_SAMPLE_RATE_TYPE_FREQUENCY:
			if rate, ok := e.SampleRate.(*api.PerformanceEventFilter_Frequency); !ok {
				s.logStatus(
					code.Code_INVALID_ARGUMENT,
					fmt.Sprintf("Frequency not properly specified for frequency sample rate"))
				continue
			} else {
				attr.SampleFreq = rate.Frequency
				attr.Freq = true
			}
		default:
			s.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("SampleRateType %d is invalid", e.SampleRateType))
			continue
		}

		counters := make([]perf.CounterEventGroupMember, 0, len(e.Events))
		for _, ev := range e.Events {
			m := perf.CounterEventGroupMember{
				Config: ev.Config,
			}
			switch ev.Type {
			case api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE:
				m.EventType = perf.EventTypeHardware
			case api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE:
				m.EventType = perf.EventTypeHardwareCache
			case api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_SOFTWARE:
				m.EventType = perf.EventTypeSoftware
			default:
				s.logStatus(
					code.Code_INVALID_ARGUMENT,
					fmt.Sprintf("PerformanceEventType %d is invalid", ev.Type))
				continue
			}
			counters = append(counters, m)
		}

		s.RegisterPerformanceEventFilter(attr, counters)
	}
}

func rewriteProcessEventFilter(pef *api.ProcessEventFilter) {
	switch pef.Type {
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
		if pef.ExecFilename != nil {
			newExpr := expression.Equal(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilename.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilename = nil
			pef.ExecFilenamePattern = nil
		} else if pef.ExecFilenamePattern != nil {
			newExpr := expression.Like(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilenamePattern.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilenamePattern = nil
		}
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
		if pef.ExitCode != nil {
			newExpr := expression.Equal(
				expression.Identifier("code"),
				expression.Value(pef.ExitCode.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExitCode = nil
		}
	}
}

func (s *Subscription) registerProcessEvents(events []*api.ProcessEventFilter) {
	type registerFunc func(*expression.Expression)

	var (
		filters       [5]*api.Expression
		subscriptions [5]registerFunc
		wildcards     [5]bool
	)

	for _, e := range events {
		// Translate deprecated fields into an expression
		rewriteProcessEventFilter(e)

		t := e.GetType()
		if t < 1 || t > api.ProcessEventType(len(subscriptions)-1) {
			s.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("ProcessEventType %d is invalid", t))
			continue
		}

		if subscriptions[t] == nil {
			switch t {
			case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
				subscriptions[t] = s.RegisterProcessExecEventFilter
			case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
				subscriptions[t] = s.RegisterProcessForkEventFilter
			case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
				subscriptions[t] = s.RegisterProcessExitEventFilter
			case api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE:
				subscriptions[t] = s.RegisterProcessUpdateEventFilter
			}
		}
		if e.FilterExpression == nil {
			wildcards[t] = true
			filters[t] = nil
		} else if !wildcards[t] {
			filters[t] = expression.LogicalOr(
				e.FilterExpression,
				filters[t])
		}
	}

	for i, f := range subscriptions {
		if f == nil {
			continue
		}
		if wildcards[i] {
			f(nil)
		} else if expr, err := expression.NewExpression(filters[i]); err == nil {
			f(expr)
		} else {
			s.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Invalid process filter expression: %v", err))
		}
	}
}

func rewriteSyscallEventFilter(sef *api.SyscallEventFilter) {
	if sef.Id != nil {
		newExpr := expression.Equal(
			expression.Identifier("id"),
			expression.Value(sef.Id.Value))
		sef.FilterExpression = expression.LogicalAnd(
			newExpr, sef.FilterExpression)
		sef.Id = nil
	}

	if sef.Type == api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER {
		if sef.Arg0 != nil {
			newExpr := expression.Equal(
				expression.Identifier("arg0"),
				expression.Value(sef.Arg0.Value))
			sef.FilterExpression = expression.LogicalAnd(
				newExpr, sef.FilterExpression)
			sef.Arg0 = nil
		}

		if sef.Arg1 != nil {
			newExpr := expression.Equal(
				expression.Identifier("arg1"),
				expression.Value(sef.Arg1.Value))
			sef.FilterExpression = expression.LogicalAnd(
				newExpr, sef.FilterExpression)
			sef.Arg1 = nil
		}

		if sef.Arg2 != nil {
			newExpr := expression.Equal(
				expression.Identifier("arg2"),
				expression.Value(sef.Arg2.Value))
			sef.FilterExpression = expression.LogicalAnd(
				newExpr, sef.FilterExpression)
			sef.Arg2 = nil
		}

		if sef.Arg3 != nil {
			newExpr := expression.Equal(
				expression.Identifier("arg3"),
				expression.Value(sef.Arg3.Value))
			sef.FilterExpression = expression.LogicalAnd(
				newExpr, sef.FilterExpression)
			sef.Arg3 = nil
		}

		if sef.Arg4 != nil {
			newExpr := expression.Equal(
				expression.Identifier("arg4"),
				expression.Value(sef.Arg4.Value))
			sef.FilterExpression = expression.LogicalAnd(
				newExpr, sef.FilterExpression)
			sef.Arg4 = nil
		}

		if sef.Arg5 != nil {
			newExpr := expression.Equal(
				expression.Identifier("arg5"),
				expression.Value(sef.Arg5.Value))
			sef.FilterExpression = expression.LogicalAnd(
				newExpr, sef.FilterExpression)
			sef.Arg5 = nil
		}
	} else if sef.Type == api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT {
		if sef.Ret != nil {
			newExpr := expression.Equal(
				expression.Identifier("ret"),
				expression.Value(sef.Ret.Value))
			sef.FilterExpression = expression.LogicalAnd(
				newExpr, sef.FilterExpression)
			sef.Ret = nil
		}
	}
}

func (s *Subscription) registerSyscallEvents(events []*api.SyscallEventFilter) {
	var enterFilter, exitFilter *api.Expression

	for _, e := range events {
		// Translate deprecated fields into an expression
		rewriteSyscallEventFilter(e)

		if !containsIDFilter(e.FilterExpression) {
			// No wildcard filters for now
			s.logStatus(
				code.Code_INVALID_ARGUMENT,
				"Wildcard syscall filter ignored")
			continue
		}

		switch t := e.GetType(); t {
		case api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER:
			enterFilter = expression.LogicalOr(enterFilter,
				e.FilterExpression)
		case api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT:
			exitFilter = expression.LogicalOr(exitFilter,
				e.FilterExpression)
		default:
			s.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("SyscallEventType %d is invalid", t))
			continue
		}
	}

	if enterFilter != nil {
		if expr, err := expression.NewExpression(enterFilter); err == nil {
			s.RegisterSyscallEnterEventFilter(expr)
		} else {
			s.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Invalid filter expression for syscall enter filter: %v", err))
		}

	}
	if exitFilter != nil {
		if expr, err := expression.NewExpression(exitFilter); err == nil {
			s.RegisterSyscallExitEventFilter(expr)
		} else {
			s.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Invalid filter expression for syscall exit filter: %v", err))
		}

	}
}

func (s *Subscription) registerTickerEvents(events []*api.TickerEventFilter) {
	for _, e := range events {
		s.RegisterTickerEventFilter(e.Interval, nil)
	}
}
