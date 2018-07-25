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

package config

import (
	"github.com/golang/glog"
	"github.com/kelseyhightower/envconfig"
)

// Global contains overridable configuration options that apply globally
var Global struct {
	// RunDir is the path to the runtime state directory for Capsule8
	RunDir string `split_words:"true" default:"/var/run/capsule8"`

	// HTTP address and port for the pprof runtime profiling endpoint.
	ProfilingListenAddr string `split_words:"true"`
}

// Sensor contains overridable configuration options for the sensor
var Sensor struct {
	// DockerContainerDir is the path to the directory used for docker
	// container local storage areas (i.e. /var/lib/docker/containers)
	DockerContainerDir string `split_words:"true" default:"/var/lib/docker/containers"`

	// OciContainerDir is the path to the directory used for the
	// container runtime's container state directories
	// (i.e. /var/run/docker/libcontainerd)
	OciContainerDir string `split_words:"true" default:"/var/run/docker/libcontainerd"`

	// Sensor gRPC API Server listen address may be specified as any of:
	//   unix:/path/to/socket
	//   127.0.0.1:8484
	//   :8484
	ListenAddr string `split_words:"true" default:"unix:/var/run/capsule8/sensor.sock"`

	// UseTLS is the boolean switch to enable TLS use. By default it
	// is false. If UseTLS is true, TLSCACertPath, TLSServerCertPath
	// and TLSServerKeyPath will need to be set.
	UseTLS bool `split_words:"true" default:"false"`

	// TLSCACertPath is the path to the file that holds the
	// certificate authority certificate for the telemetry server.
	// This will only be used if UseTLS is true.
	TLSCACertPath string `split_words:"true" default:"/var/lib/capsule8/tls/ca.crt"`

	// TLSServerCertPath is the path to the file that holds the
	// server certificate for the telemetry server. This will only be
	// used if UseTLS is true.
	TLSServerCertPath string `split_words:"true" default:"/var/lib/capsule8/tls/server.crt"`

	// TLSServerKeyPath is the path to the file that holds the
	// server key for the telemetry server. This will only be used
	// if UseTLS is true.
	TLSServerKeyPath string `split_words:"true" default:"/var/lib/capsule8/tls/server.key"`

	// Names of cgroups to monitor for events. Each cgroup specified must
	// exist within the perf_event cgroup hierarchy. For example, if this
	// is set to "docker", the Sensor will monitor containers for events
	// and ignore processes not running in Docker containers. To monitor
	// the entire system, use "" or "/" as the cgroup name.
	CgroupName []string `split_words:"true"`

	// Ignore missing debugfs/tracefs mount (useful for automated testing)
	DontMountTracing bool `split_words:"true"`

	// Ignore missing perf_event cgroup filesystem mount
	DontMountPerfEvent bool `split_words:"true"`

	//
	// Performance knobs below here
	//

	// The default size of ring buffers used for kernel perf_event
	// monitors. The size is defined in units of pages.
	RingBufferPages int `split_words:"true" default:"8"`

	// The default buffer length for Go channels used internally
	ChannelBufferLength int `split_words:"true" default:"1024"`

	// The size of the process info cache. If the system pid_max is greater
	// than this size, a less performant method of caching will be used.
	ProcessInfoCacheSize uint `split_words:"true" default:"131072"`
}

func init() {
	if err := envconfig.Process("CAPSULE8", &Global); err != nil {
		glog.Fatal(err)
	}

	if err := envconfig.Process("CAPSULE8_SENSOR", &Sensor); err != nil {
		glog.Fatal(err)
	}
}
