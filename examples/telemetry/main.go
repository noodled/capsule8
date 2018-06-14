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

// Sample Telemetry API client

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	api "github.com/capsule8/capsule8/api/v0"
	"github.com/capsule8/capsule8/pkg/expression"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes/wrappers"

	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"
)

var config struct {
	server      string
	image       string
	json        bool
	prettyPrint bool
}

func init() {
	flag.StringVar(&config.server, "server",
		"unix:/var/run/capsule8/sensor.sock",
		"Capsule8 gRPC API server address")

	flag.StringVar(&config.image, "image", "",
		"Container image wildcard pattern to monitor")
	flag.BoolVar(&config.json, "json", false,
		"Output telemetry events as JSON")
	flag.BoolVar(&config.prettyPrint, "prettyprint", false,
		"Pretty print JSON telemetry events")
}

// Custom gRPC Dialer that understands "unix:/path/to/sock" as well as TCP addrs
func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	var network, address string

	parts := strings.Split(addr, ":")
	if len(parts) > 1 && parts[0] == "unix" {
		network = "unix"
		address = parts[1]
	} else {
		network = "tcp"
		address = addr
	}

	return net.DialTimeout(network, address, timeout)
}

func createSubscription() *api.Subscription {
	processEvents := []*api.ProcessEventFilter{
		//
		// Get all process lifecycle events
		//
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_FORK,
		},
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
		},
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
		},
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE,
		},
	}

	syscallEvents := []*api.SyscallEventFilter{
		// Get all open(2) syscalls
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,

			Id: &wrappers.Int64Value{
				Value: 2, // SYS_OPEN
			},
		},

		// An example of negative filters:
		// Get all setuid(2) calls that are not root
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,

			Id: &wrappers.Int64Value{
				Value: 105, // SYS_SETUID
			},

			FilterExpression: expression.NotEqual(
				expression.Identifier("arg0"),
				expression.Value(uint64(0))),
		},
	}

	fileEvents := []*api.FileEventFilter{
		//
		// Get all attempts to open files matching glob *foo*
		//
		&api.FileEventFilter{
			Type: api.FileEventType_FILE_EVENT_TYPE_OPEN,

			//
			// The glob accepts a wild card character
			// (*,?) and character classes ([).
			//
			FilenamePattern: &wrappers.StringValue{
				Value: "*foo*",
			},
		},
	}

	sinFamilyFilter := expression.Equal(
		expression.Identifier("sin_family"),
		expression.Value(uint16(2)))
	kernelCallEvents := []*api.KernelFunctionCallFilter{
		//
		// Install a kprobe on connect(2)
		//
		&api.KernelFunctionCallFilter{
			Type:   api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_ENTER,
			Symbol: "SyS_connect",
			Arguments: map[string]string{
				"sin_family": "+0(%si):u16",
				"sin_port":   "+2(%si):u16",
				"sin_addr":   "+4(%si):u32",
			},
			FilterExpression: sinFamilyFilter,
		},
	}

	containerEvents := []*api.ContainerEventFilter{
		//
		// Get all container lifecycle events
		//
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED,
		},
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING,
		},
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED,
		},
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED,
		},
	}

	// Ticker events are used for debugging and performance testing
	tickerEvents := []*api.TickerEventFilter{
		&api.TickerEventFilter{
			Interval: int64(1 * time.Second),
		},
	}

	chargenEvents := []*api.ChargenEventFilter{
		/*
			&api.ChargenEventFilter{
				Length: 16,
			},
		*/
	}

	eventFilter := &api.EventFilter{
		ProcessEvents:   processEvents,
		SyscallEvents:   syscallEvents,
		KernelEvents:    kernelCallEvents,
		FileEvents:      fileEvents,
		ContainerEvents: containerEvents,
		TickerEvents:    tickerEvents,
		ChargenEvents:   chargenEvents,
	}

	sub := &api.Subscription{
		EventFilter: eventFilter,
	}

	if config.image != "" {
		fmt.Fprintf(os.Stderr,
			"Watching for container images matching %s\n",
			config.image)

		containerFilter := &api.ContainerFilter{}

		containerFilter.ImageNames =
			append(containerFilter.ImageNames, config.image)

		sub.ContainerFilter = containerFilter
	}

	return sub
}

func main() {
	var marshaler *jsonpb.Marshaler

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context on control-C
	signals := make(chan os.Signal)
	signal.Notify(signals, os.Interrupt)

	go func() {
		<-signals
		cancel()
	}()

	// Create telemetry service client
	conn, err := grpc.DialContext(ctx, config.server,
		grpc.WithDialer(dialer),
		grpc.WithBlock(),
		grpc.WithTimeout(1*time.Second),
		grpc.WithInsecure())

	c := api.NewTelemetryServiceClient(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grpc.Dial: %s\n", err)
		os.Exit(1)
	}

	stream, err := c.GetEvents(ctx, &api.GetEventsRequest{
		Subscription: createSubscription(),
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "GetEvents: %s\n", err)
		os.Exit(1)
	}

	if config.json {
		marshaler = &jsonpb.Marshaler{EmitDefaults: true}

		if config.prettyPrint {
			marshaler.Indent = "\t"
		}
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Recv: %s\n", err)
			os.Exit(1)
		}

		if len(ev.Statuses) > 1 ||
			(len(ev.Statuses) == 1 &&
				ev.Statuses[0].Code != int32(code.Code_OK)) {
			for _, s := range ev.Statuses {
				if config.json {
					msg, err := marshaler.MarshalToString(s)
					if err != nil {
						fmt.Fprintf(os.Stderr,
							"Unable to decode event: %v", err)
						continue
					}
					fmt.Println(msg)
				} else {
					fmt.Println(s)
				}
			}

		}

		for _, e := range ev.Events {
			if config.json {
				msg, err := marshaler.MarshalToString(e)
				if err != nil {
					fmt.Fprintf(os.Stderr,
						"Unable to decode event: %v", err)
					continue
				}
				fmt.Println(msg)
			} else {
				fmt.Println(e)
			}
		}
	}
}
