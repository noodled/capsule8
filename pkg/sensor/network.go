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

var networkAttemptEventTypes = expression.FieldTypeMap{
	"fd": expression.ValueTypeUnsignedInt64,
}

var networkAttemptWithAddressEventTypes = expression.FieldTypeMap{
	"fd":             expression.ValueTypeUnsignedInt64,
	"sa_family":      expression.ValueTypeUnsignedInt16,
	"sin_port":       expression.ValueTypeUnsignedInt16,
	"sin_addr":       expression.ValueTypeUnsignedInt32,
	"sun_path":       expression.ValueTypeString,
	"sin6_port":      expression.ValueTypeUnsignedInt16,
	"sin6_addr_high": expression.ValueTypeUnsignedInt64,
	"sin6_addr_low":  expression.ValueTypeUnsignedInt64,
}

var networkListenAttemptEventTypes = expression.FieldTypeMap{
	"fd":      expression.ValueTypeUnsignedInt64,
	"backlog": expression.ValueTypeUnsignedInt64,
}

var networkResultEventTypes = expression.FieldTypeMap{
	"ret": expression.ValueTypeSignedInt64,
}

const (
	networkKprobeBindSymbol    = "sys_bind"
	networkKprobeBindFetchargs = "fd=%di sa_family=+0(%si):u16 " +
		"sin_port=+2(%si):u16 sin_addr=+4(%si):u32 " +
		"sun_path=+2(%si):string " +
		"sin6_port=+2(%si):u16 sin6_addr_high=+8(%si):u64 sin6_addr_low=+16(%si):u64"

	networkKprobeConnectSymbol    = "sys_connect"
	networkKprobeConnectFetchargs = "fd=%di sa_family=+0(%si):u16 " +
		"sin_port=+2(%si):u16 sin_addr=+4(%si):u32 " +
		"sun_path=+2(%si):string " +
		"sin6_port=+2(%si):u16 sin6_addr_high=+8(%si):u64 sin6_addr_low=+16(%si):u64"

	networkKprobeSendmsgSymbol    = "sys_sendmsg"
	networkKprobeSendmsgFetchargs = "fd=%di sa_family=+0(+0(%si)):u16 " +
		"sin_port=+2(+0(%si)):u16 sin_addr=+4(+0(%si)):u32 " +
		"sun_path=+2(+0(%si)):string " +
		"sin6_port=+2(+0(%si)):u16 sin6_addr_high=+8(+0(%si)):u64 sin6_addr_low=+16(+0(%si)):u64"

	networkKprobeSendtoSymbol    = "sys_sendto"
	networkKprobeSendtoFetchargs = "fd=%di sa_family=+0(%r8):u16 " +
		"sin_port=+2(%r8):u16 sin_addr=+4(%r8):u32 " +
		"sun_path=+2(%r8):string " +
		"sin6_port=+2(%r8):u16 sin6_addr_high=+8(%r8):u64 sin6_addr_low=+16(%r8):u64"
)

func (s *Subscription) newNetworkEvent(
	eventType api.NetworkEventType,
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) *api.TelemetryEvent {
	// If this event contains a network address, throw away any family that
	// we do not support without doing the extra work of creating an event
	// just to throw it away
	family, haveFamily := data["sa_family"].(uint16)
	if haveFamily {
		switch family {
		case 1: // AF_LOCAL
			break
		case 2: // AF_INET
			break
		case 10: // AF_INET6
			break
		default:
			return nil
		}
	}

	event := s.sensor.NewEventFromSample(sample, data)
	if event == nil {
		return nil
	}
	event.Event = &api.TelemetryEvent_Network{
		Network: &api.NetworkEvent{
			Type: eventType,
		},
	}
	network := event.Event.(*api.TelemetryEvent_Network).Network

	if haveFamily {
		switch family {
		case 1: // AF_LOCAL
			network.Address = &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
				Address: &api.NetworkAddress_LocalAddress{
					LocalAddress: data["sun_path"].(string),
				},
			}
		case 2: // AF_INET
			network.Address = &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET,
				Address: &api.NetworkAddress_Ipv4Address{
					Ipv4Address: &api.IPv4AddressAndPort{
						Address: &api.IPv4Address{
							Address: data["sin_addr"].(uint32),
						},
						Port: uint32(data["sin_port"].(uint16)),
					},
				},
			}
		case 10: // AF_INET6
			network.Address = &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET6,
				Address: &api.NetworkAddress_Ipv6Address{
					Ipv6Address: &api.IPv6AddressAndPort{
						Address: &api.IPv6Address{
							High: data["sin6_addr_high"].(uint64),
							Low:  data["sin6_addr_low"].(uint64),
						},
						Port: uint32(data["sin6_port"].(uint16)),
					},
				},
			}
		default:
			// This shouldn't be reachable
			return nil
		}
	}

	if fd, ok := data["fd"]; ok {
		network.Sockfd = fd.(uint64)
	}

	if ret, ok := data["ret"]; ok {
		network.Result = ret.(int64)
	}

	return event
}

func (s *Subscription) decodeSysEnterAccept(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_ATTEMPT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysExitAccept(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_RESULT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysBind(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_ATTEMPT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysExitBind(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_RESULT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysConnect(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_ATTEMPT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysExitConnect(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_RESULT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysEnterListen(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT, sample, data)

	network := event.Event.(*api.TelemetryEvent_Network).Network
	network.Backlog = data["backlog"].(uint64)

	return event, nil
}

func (s *Subscription) decodeSysExitListen(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_RESULT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysEnterRecvfrom(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_ATTEMPT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysExitRecvfrom(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_RESULT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysSendto(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_ATTEMPT, sample, data)
	return event, nil
}

func (s *Subscription) decodeSysExitSendto(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := s.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_RESULT, sample, data)
	return event, nil
}

// RegisterNetworkAcceptAttemptEventFilter registers a network accept attempt
// event filter with a subscription.
func (s *Subscription) RegisterNetworkAcceptAttemptEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_enter_accept",
		s.decodeSysEnterAccept,
		expr, networkAttemptEventTypes)
	s.registerTracepoint("syscalls/sys_enter_accept4",
		s.decodeSysEnterAccept,
		expr, networkAttemptEventTypes)
}

// RegisterNetworkAcceptResultEventFilter registers a network accept result
// event filter with a subscription.
func (s *Subscription) RegisterNetworkAcceptResultEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_exit_accept",
		s.decodeSysExitAccept,
		expr, networkResultEventTypes)
	s.registerTracepoint("syscalls/sys_exit_accept4",
		s.decodeSysExitAccept,
		expr, networkResultEventTypes)
}

// RegisterNetworkBindAttemptEventFilter registers a network bind attempt event
// filter with a subscription.
func (s *Subscription) RegisterNetworkBindAttemptEventFilter(expr *expression.Expression) {
	s.registerKprobe(networkKprobeBindSymbol, false,
		networkKprobeBindFetchargs, s.decodeSysBind,
		expr, networkAttemptWithAddressEventTypes)
}

// RegisterNetworkBindResultEventFilter registers a network bind result event
// filter with a subscription.
func (s *Subscription) RegisterNetworkBindResultEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_exit_bind",
		s.decodeSysExitBind,
		expr, networkResultEventTypes)
}

// RegisterNetworkConnectAttemptEventFilter registers a network connect attempt
// event filter with a subscription.
func (s *Subscription) RegisterNetworkConnectAttemptEventFilter(expr *expression.Expression) {
	s.registerKprobe(networkKprobeConnectSymbol, false,
		networkKprobeConnectFetchargs, s.decodeSysConnect,
		expr, networkAttemptWithAddressEventTypes)
}

// RegisterNetworkConnectResultEventFilter registers a network connect result
// event filter with a subscription.
func (s *Subscription) RegisterNetworkConnectResultEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_exit_connect",
		s.decodeSysExitConnect,
		expr, networkResultEventTypes)
}

// RegisterNetworkListenAttemptEventFilter registers a network listen attempt
// event filter with a subscription.
func (s *Subscription) RegisterNetworkListenAttemptEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_enter_listen",
		s.decodeSysEnterListen,
		expr, networkListenAttemptEventTypes)
}

// RegisterNetworkListenResultEventFilter registers a network listen result
// event filter with a subscription.
func (s *Subscription) RegisterNetworkListenResultEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_exit_listen",
		s.decodeSysExitListen,
		expr, networkResultEventTypes)
}

// RegisterNetworkRecvfromAttemptEventFilter registers a network recvfrom
// attempt event filter with a subscription.
func (s *Subscription) RegisterNetworkRecvfromAttemptEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_enter_recvfrom",
		s.decodeSysEnterRecvfrom,
		expr, networkAttemptEventTypes)
	s.registerTracepoint("syscalls/sys_enter_recvmsg",
		s.decodeSysEnterRecvfrom,
		expr, networkAttemptEventTypes)
}

// RegisterNetworkRecvfromResultEventFilter registers a network recvfrom result
// event filter with a subscription.
func (s *Subscription) RegisterNetworkRecvfromResultEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_exit_recvfrom",
		s.decodeSysExitRecvfrom,
		expr, networkResultEventTypes)
	s.registerTracepoint("syscalls/sys_exit_recvmsg",
		s.decodeSysExitRecvfrom,
		expr, networkResultEventTypes)
}

// RegisterNetworkSendtoAttemptEventFilter registers a network sendto attempt
// event filter with a subscription.
func (s *Subscription) RegisterNetworkSendtoAttemptEventFilter(expr *expression.Expression) {
	s.registerKprobe(networkKprobeSendmsgSymbol, false,
		networkKprobeSendmsgFetchargs, s.decodeSysSendto,
		expr, networkAttemptWithAddressEventTypes)
	s.registerKprobe(networkKprobeSendtoSymbol, false,
		networkKprobeSendtoFetchargs, s.decodeSysSendto,
		expr, networkAttemptWithAddressEventTypes)
}

// RegisterNetworkSendtoResultEventFilter registers a network sendto result
// event filter with a subscription.
func (s *Subscription) RegisterNetworkSendtoResultEventFilter(expr *expression.Expression) {
	s.registerTracepoint("syscalls/sys_exit_sendmsg",
		s.decodeSysExitSendto,
		expr, networkResultEventTypes)
	s.registerTracepoint("syscalls/sys_exit_sendto",
		s.decodeSysExitSendto,
		expr, networkResultEventTypes)
}
