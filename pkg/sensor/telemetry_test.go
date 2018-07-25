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
	"testing"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"
)

func TestNewTelemetryEvent(t *testing.T) {
	data := TelemetryEventData{
		EventID:        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678./",
		MonotimeNanos:  2837465342,
		SequenceNumber: 293847,
		ProcessID:      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678./",
		PID:            872364,
		TGID:           28734,
		CPU:            3,
		HasCredentials: true,
		Credentials:    Cred{12, 34, 56, 78, 90, 98, 76, 54},
		Container: ContainerInfo{
			ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
			Name:       "capsule8-sensor-container",
			ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
			ImageName:  "capsule8-sensor-image",
			Pid:        872364,
			ExitCode:   255,
			Runtime:    ContainerRuntimeDocker,
			State:      ContainerStateRunning,
			JSONConfig: "This is the JSON config that isn't actually JSON",
			OCIConfig:  "This is the OCI config that isn't real",
		},
	}

	e := newTelemetryEvent(data)
	assert.Equal(t, data.EventID, e.Id)
	assert.Equal(t, data.ProcessID, e.ProcessId)
	assert.Equal(t, data.PID, int(e.ProcessPid))
	assert.Equal(t, data.Container.ID, e.ContainerId)
	assert.Equal(t, data.SensorID, e.SensorId)
	assert.Equal(t, data.SequenceNumber, e.SensorSequenceNumber)
	assert.Equal(t, data.MonotimeNanos, e.SensorMonotimeNanos)
	assert.Nil(t, e.ProcessLineage)
	assert.Equal(t, data.Container.Name, e.ContainerName)
	assert.Equal(t, data.Container.ImageID, e.ImageId)
	assert.Equal(t, data.Container.ImageName, e.ImageName)
	assert.Equal(t, data.CPU, uint32(e.Cpu))
	assert.Equal(t, data.Credentials.UID, e.Credentials.Uid)
	assert.Equal(t, data.Credentials.GID, e.Credentials.Gid)
	assert.Equal(t, data.Credentials.EUID, e.Credentials.Euid)
	assert.Equal(t, data.Credentials.EGID, e.Credentials.Egid)
	assert.Equal(t, data.Credentials.SUID, e.Credentials.Suid)
	assert.Equal(t, data.Credentials.SGID, e.Credentials.Sgid)
	assert.Equal(t, data.Credentials.FSUID, e.Credentials.Fsuid)
	assert.Equal(t, data.Credentials.FSGID, e.Credentials.Fsgid)
	assert.Equal(t, data.TGID, int(e.ProcessTgid))
}

func TestTranslateNetworkAddress(t *testing.T) {
	type testCase struct {
		data     NetworkAddressTelemetryEventData
		expected *api.NetworkAddress
	}

	testCases := []testCase{
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family:   unix.AF_LOCAL,
				UnixPath: "/tmp/capsule8/local.socket",
			},
			expected: &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
				Address: &api.NetworkAddress_LocalAddress{
					LocalAddress: "/tmp/capsule8/local.socket",
				},
			},
		},
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family:      unix.AF_INET,
				IPv4Address: 0x7f000001,
				IPv4Port:    0x1f90,
			},
			expected: &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET,
				Address: &api.NetworkAddress_Ipv4Address{
					Ipv4Address: &api.IPv4AddressAndPort{
						Address: &api.IPv4Address{
							Address: 0x7f000001,
						},
						Port: 0x1f90,
					},
				},
			},
		},
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family:          unix.AF_INET6,
				IPv6AddressHigh: 0x1122334455667788,
				IPv6AddressLow:  0x9900aabbccddeeff,
				IPv6Port:        0x01bb,
			},
			expected: &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET6,
				Address: &api.NetworkAddress_Ipv6Address{
					Ipv6Address: &api.IPv6AddressAndPort{
						Address: &api.IPv6Address{
							High: 0x1122334455667788,
							Low:  0x9900aabbccddeeff,
						},
						Port: 0x01bb,
					},
				},
			},
		},
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family: unix.AF_APPLETALK,
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		got := translateNetworkAddress(tc.data)
		assert.Equal(t, tc.expected, got)
	}
}

func TestTranslateEvent(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := sensor.NewSubscription()
	require.NotNil(t, s)

	type testCase struct {
		event    TelemetryEvent
		expected *api.TelemetryEvent
	}

	testCases := []testCase{
		// Chargen
		testCase{
			event: ChargenTelemetryEvent{
				Index:      65,
				Characters: "abcdefghijklmnopqrstuvwxyz",
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Chargen{
					Chargen: &api.ChargenEvent{
						Index:      65,
						Characters: "abcdefghijklmnopqrstuvwxyz",
					},
				},
			},
		},
		// ContainerCreated
		testCase{
			event: ContainerCreatedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerDestroyed
		testCase{
			event: ContainerDestroyedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerExited (WaitStatus.Exited)
		testCase{
			event: ContainerExitedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   88 << 8,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						ExitCode:         88 << 8,
						ExitStatus:       88,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerExited (WaitStatus.Signaled SIGSEGV w/ CoreDump)
		testCase{
			event: ContainerExitedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   int(unix.SIGSEGV) | 0x80,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						ExitCode:         int32(unix.SIGSEGV) | 0x80,
						ExitSignal:       uint32(unix.SIGSEGV),
						ExitCoreDumped:   true,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerRunning
		testCase{
			event: ContainerRunningTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerUpdated
		testCase{
			event: ContainerUpdatedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// FileOpen
		testCase{
			event: FileOpenTelemetryEvent{
				Filename: "/path/to/foo.bar",
				Flags:    8276354,
				Mode:     0644,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_File{
					File: &api.FileEvent{
						Type:      api.FileEventType_FILE_EVENT_TYPE_OPEN,
						Filename:  "/path/to/foo.bar",
						OpenFlags: 8276354,
						OpenMode:  0644,
					},
				},
			},
		},
		// KernelFunctionCall
		testCase{
			event: KernelFunctionCallTelemetryEvent{
				Arguments: perf.TraceEventSampleData{
					"bytes":  []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
					"string": "string_value",
					"sint8":  int8(-8),
					"sint16": int16(-16),
					"sint32": int32(-32),
					"sint64": int64(-64),
					"uint8":  uint8(8),
					"uint16": uint16(16),
					"uint32": uint32(32),
					"uint64": uint64(64),
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_KernelCall{
					KernelCall: &api.KernelFunctionCallEvent{
						Arguments: map[string]*api.KernelFunctionCallEvent_FieldValue{
							"bytes": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_BYTES,
								Value: &api.KernelFunctionCallEvent_FieldValue_BytesValue{
									BytesValue: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
								},
							},
							"string": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_STRING,
								Value: &api.KernelFunctionCallEvent_FieldValue_StringValue{
									StringValue: "string_value",
								},
							},
							"sint8": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT8,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-8),
								},
							},
							"sint16": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT16,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-16),
								},
							},
							"sint32": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT32,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-32),
								},
							},
							"sint64": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT64,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-64),
								},
							},
							"uint8": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT8,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(8),
								},
							},
							"uint16": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT16,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(16),
								},
							},
							"uint32": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT32,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(32),
								},
							},
							"uint64": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT64,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(64),
								},
							},
						},
					},
				},
			},
		},
		// NetworkAcceptAttemptTelemetryEvent
		testCase{
			event: NetworkAcceptAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_ATTEMPT,
						Sockfd: 82734,
					},
				},
			},
		},
		// NetworkAcceptResultTelemetryEvent
		testCase{
			event: NetworkAcceptResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkBindAttemptTelemetryEvent
		testCase{
			event: NetworkBindAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				NetworkAddressTelemetryEventData: NetworkAddressTelemetryEventData{
					Family:   unix.AF_LOCAL,
					UnixPath: "/path/to/local.socket",
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_ATTEMPT,
						Sockfd: 82734,
						Address: &api.NetworkAddress{
							Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
							Address: &api.NetworkAddress_LocalAddress{
								LocalAddress: "/path/to/local.socket",
							},
						},
					},
				},
			},
		},
		// NetworkBindResultTelemetryEvent
		testCase{
			event: NetworkBindResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkConnectAttemptTelemetryEvent
		testCase{
			event: NetworkConnectAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				NetworkAddressTelemetryEventData: NetworkAddressTelemetryEventData{
					Family:   unix.AF_LOCAL,
					UnixPath: "/path/to/local.socket",
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_ATTEMPT,
						Sockfd: 82734,
						Address: &api.NetworkAddress{
							Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
							Address: &api.NetworkAddress_LocalAddress{
								LocalAddress: "/path/to/local.socket",
							},
						},
					},
				},
			},
		},
		// NetworkConnectResultTelemetryEvent
		testCase{
			event: NetworkConnectResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkListenAttemptTelemetryEvent
		testCase{
			event: NetworkListenAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				Backlog: 24576,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:    api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT,
						Sockfd:  82734,
						Backlog: 24576,
					},
				},
			},
		},
		// NetworkListenResultTelemetryEvent
		testCase{
			event: NetworkListenResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkRecvfromAttemptTelemetryEvent
		testCase{
			event: NetworkRecvfromAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_ATTEMPT,
						Sockfd: 82734,
					},
				},
			},
		},
		// NetworkRecvfromResultTelemetryEvent
		testCase{
			event: NetworkRecvfromResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkSendtoAttemptTelemetryEvent
		testCase{
			event: NetworkSendtoAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				NetworkAddressTelemetryEventData: NetworkAddressTelemetryEventData{
					Family:   unix.AF_LOCAL,
					UnixPath: "/path/to/local.socket",
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_ATTEMPT,
						Sockfd: 82734,
						Address: &api.NetworkAddress{
							Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
							Address: &api.NetworkAddress_LocalAddress{
								LocalAddress: "/path/to/local.socket",
							},
						},
					},
				},
			},
		},
		// NetworkSendtoResultTelemetryEvent
		testCase{
			event: NetworkSendtoResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// PerformanceTelemetryEvent
		testCase{
			event: PerformanceTelemetryEvent{
				TotalTimeEnabled: 23984756,
				TotalTimeRunning: 92873456,
				Counters: []perf.CounterEventValue{
					perf.CounterEventValue{
						EventType: perf.EventTypeHardware,
						Config:    29384756,
						Value:     20938457,
					},
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Performance{
					Performance: &api.PerformanceEvent{
						TotalTimeEnabled: 23984756,
						TotalTimeRunning: 92873456,
						Values: []*api.PerformanceEventValue{
							&api.PerformanceEventValue{
								Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE,
								Config: 29384756,
								Value:  20938457,
							},
						},
					},
				},
			},
		},
		// ProcessExec
		testCase{
			event: ProcessExecTelemetryEvent{
				Filename:    "/bin/bash",
				CommandLine: []string{"bash", "-l"},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:            api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
						ExecFilename:    "/bin/bash",
						ExecCommandLine: []string{"bash", "-l"},
					},
				},
			},
		},
		// ProcessExit (WaitStatus.Exited)
		testCase{
			event: ProcessExitTelemetryEvent{
				ExitCode:   88 << 8,
				ExitStatus: 88,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:       api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
						ExitCode:   88 << 8,
						ExitStatus: 88,
					},
				},
			},
		},
		// ProcessExit (WaitStatus.Signaled SIGSEGV w/ CoreDump)
		testCase{
			event: ProcessExitTelemetryEvent{
				ExitCode:       int32(unix.SIGSEGV) | 0x80,
				ExitSignal:     uint32(unix.SIGSEGV),
				ExitCoreDumped: true,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:           api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
						ExitCode:       int32(unix.SIGSEGV) | 0x80,
						ExitSignal:     uint32(unix.SIGSEGV),
						ExitCoreDumped: true,
					},
				},
			},
		},
		// ProcessFork
		testCase{
			event: ProcessForkTelemetryEvent{
				ChildPID:       872364,
				ChildProcessID: "some random string for a child process id",
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:         api.ProcessEventType_PROCESS_EVENT_TYPE_FORK,
						ForkChildId:  "some random string for a child process id",
						ForkChildPid: 872364,
					},
				},
			},
		},
		// ProcessUpdate
		testCase{
			event: ProcessUpdateTelemetryEvent{
				CWD: "/var/run/capsule8",
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:      api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE,
						UpdateCwd: "/var/run/capsule8",
					},
				},
			},
		},
		// SyscallEnter
		testCase{
			event: SyscallEnterTelemetryEvent{
				ID:        374186,
				Arguments: [6]uint64{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Syscall{
					Syscall: &api.SyscallEvent{
						Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,
						Id:   374186,
						Arg0: 0x11,
						Arg1: 0x22,
						Arg2: 0x33,
						Arg3: 0x44,
						Arg4: 0x55,
						Arg5: 0x66,
					},
				},
			},
		},
		// SyscallExit
		testCase{
			event: SyscallExitTelemetryEvent{
				ID:     987364,
				Return: 9286745,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Syscall{
					Syscall: &api.SyscallEvent{
						Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT,
						Id:   987364,
						Ret:  9286745,
					},
				},
			},
		},
		// Ticker
		testCase{
			event: TickerTelemetryEvent{
				Seconds:     2347856,
				Nanoseconds: 238764529,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Ticker{
					Ticker: &api.TickerEvent{
						Seconds:     2347856,
						Nanoseconds: 238764529,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		got := s.translateEvent(tc.event)
		assert.Equal(t, tc.expected, got)
	}
}
