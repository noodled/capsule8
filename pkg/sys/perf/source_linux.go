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

package perf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/proc"
	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

var (
	clockOnce   sync.Once
	haveClockID bool
	timeBase    int64
	timeOffsets []int64
)

// Go does not provide fcntl(). We need to provide it for ourselves
func fcntl(fd, cmd int, flag uintptr) (uintptr, error) {
	r1, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), flag)
	return r1, errno
}

// perfEventOpen is a raw interface to the perf_event_open syscall. Do not do
// any unnecessary mangling of EventAttr here (such as UseClockID) because this
// is used at start up to make the determination of whether that sort of
// mangling should be done.
func perfEventOpen(attr EventAttr, pid, cpu, groupFD int, flags uintptr) (int, error) {
	buf := new(bytes.Buffer)
	attr.write(buf)
	b := buf.Bytes()

	r1, _, errno := unix.Syscall6(unix.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&b[0])),
		uintptr(pid), uintptr(cpu), uintptr(groupFD), uintptr(flags), uintptr(0))
	if errno != 0 {
		return int(-1), errno
	}
	return int(r1), nil
}

type defaultEventSource struct {
	fd       int
	streamID int
	parent   *defaultEventSourceLeader
}

func (s *defaultEventSource) Close() error {
	if s.fd != 1 {
		if err := unix.Close(s.fd); err != nil {
			return err
		}
		s.fd = -1
	}
	return nil
}

func (s *defaultEventSource) Disable() error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(s.fd), PERF_EVENT_IOC_DISABLE, 1); errno != 0 {
		return errno
	}
	return nil
}
func (s *defaultEventSource) Enable() error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(s.fd), PERF_EVENT_IOC_ENABLE, 1); errno != 0 {
		return errno
	}
	return nil
}

func (s *defaultEventSource) SetFilter(filter string) error {
	if f, err := unix.BytePtrFromString(filter); err != nil {
		return err
	} else if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(s.fd), PERF_EVENT_IOC_SET_FILTER, uintptr(unsafe.Pointer(f))); errno != 0 {
		return errno
	}
	return nil
}

func (s *defaultEventSource) SourceID() uint64 {
	return uint64(s.streamID)
}

type defaultEventSourceLeader struct {
	defaultEventSource
	pid        int
	cpu        int
	flags      uintptr
	rb         *ringBuffer
	controller *defaultEventSourceController
}

func (s *defaultEventSourceLeader) Close() error {
	if s.rb != nil {
		if err := s.rb.unmap(); err != nil {
			return err
		}
		s.rb = nil
	}
	if err := s.defaultEventSource.Close(); err != nil {
		return err
	}
	atomic.AddInt64(&s.controller.leaderCount, -1)
	return nil
}

func (s *defaultEventSourceLeader) NewEventSource(
	attr EventAttr,
	flags uintptr,
) (EventSource, error) {
	childSource := &defaultEventSource{
		parent: s,
	}

	if haveClockID {
		attr.UseClockID = true
		attr.ClockID = unix.CLOCK_MONOTONIC_RAW
	} else {
		attr.UseClockID = false
		attr.ClockID = 0
	}
	var err error
	childSource.fd, err = perfEventOpen(attr, s.pid, s.cpu, s.fd, flags)
	if err != nil {
		return nil, err
	}

	if childSource.streamID, err = unix.IoctlGetInt(childSource.fd, PERF_EVENT_IOC_ID); err != nil {
		childSource.Close()
		return nil, err
	}

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(childSource.fd),
	}
	if err = unix.EpollCtl(s.controller.epollFD, unix.EPOLL_CTL_ADD, childSource.fd, &event); err != nil {
		childSource.Close()
		return nil, err
	}

	return childSource, nil
}

func (s *defaultEventSourceLeader) Read(
	attrMap map[uint64]EventAttr,
	f func(Sample, error),
) {
	s.rb.read(func(data []byte) {
		r := bytes.NewReader(data)
		for r.Len() > 0 {
			sample := Sample{}
			err := sample.read(r, nil, attrMap)
			sample.Time = uint64(int64(sample.Time) -
				timeOffsets[s.cpu] + timeBase)
			switch record := sample.Record.(type) {
			case *SampleRecord:
				// Adjust the sample time so that it
				// matches the normalized timestamp.
				record.Time = sample.Time
			}
			f(sample, err)
		}
	})
}

type defaultEventSourceController struct {
	epollFD            int
	pipe               [2]int
	ncpu               int
	ringBufferNumPages int
	leaderCount        int64
}

func newDefaultEventSourceController(
	opts eventMonitorOptions,
) (c *defaultEventSourceController, err error) {
	clockOnce.Do(func() {
		attr := EventAttr{
			SamplePeriod:    1,
			Disabled:        true,
			UseClockID:      true,
			ClockID:         unix.CLOCK_MONOTONIC_RAW,
			Watermark:       true,
			WakeupWatermark: 1,
		}
		var fd int
		if fd, err = perfEventOpen(attr, 0, -1, -1, 0); err == nil {
			glog.V(1).Infof("EventMonitor is using ClockID CLOCK_MONOTONIC_RAW")
			unix.Close(fd)
			haveClockID = true
		}
		err = calculateTimeOffsets(opts.procfs)
	})
	if err != nil {
		return
	}

	c = &defaultEventSourceController{
		epollFD:            -1,
		pipe:               [2]int{-1, -1},
		ncpu:               opts.procfs.NumCPU(),
		ringBufferNumPages: opts.ringBufferNumPages,
	}
	defer func() {
		if err != nil {
			c.Close()
			c = nil
		}
	}()

	if c.epollFD, err = unix.EpollCreate1(0); err != nil {
		return
	}

	if err = unix.Pipe(c.pipe[:]); err != nil {
		return
	}
	f, _ := fcntl(c.pipe[0], syscall.F_GETFL, 0)
	fcntl(c.pipe[0], syscall.F_SETFL, f|syscall.O_NONBLOCK)

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     -1,
	}
	err = unix.EpollCtl(c.epollFD, unix.EPOLL_CTL_ADD, c.pipe[0], &event)

	return
}

func collectReferenceSamples(ncpu int) (int64, int64, []int64, error) {
	referenceEventAttr := EventAttr{
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_CPU_CLOCK,
		SampleFreq:   1,
		SampleType:   PERF_SAMPLE_TIME,
		Disabled:     true,
		Freq:         true,
		WakeupEvents: 1,
	}

	rbs := make([]*ringBuffer, ncpu)
	pollfds := make([]unix.PollFd, ncpu)
	for cpu := 0; cpu < ncpu; cpu++ {
		fd, err := perfEventOpen(referenceEventAttr, -1, cpu, -1, 0)
		if err != nil {
			err = fmt.Errorf("Couldn't open reference event: %s", err)
			return 0, 0, nil, err
		}
		defer unix.Close(fd)
		pollfds[cpu] = unix.PollFd{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		}

		if rbs[cpu], err = newRingBuffer(fd, 1); err != nil {
			err = fmt.Errorf("Couldn't allocate ringbuffer: %s", err)
			return 0, 0, nil, err
		}
		defer rbs[cpu].unmap()
	}

	// Enable all of the events we just registered
	for _, p := range pollfds {
		unix.Syscall(unix.SYS_IOCTL, uintptr(p.Fd), PERF_EVENT_IOC_ENABLE, 1)
	}

	var firstTime int64
	startTime := sys.CurrentMonotonicRaw()

	// Read all samples from each group, but keep only the first for each
	// Don't wait forever. Return a timeout error if samples don't arrive
	// within 2 seconds.
	const timeout = 2 * time.Second
	glog.V(2).Infof("Calculating CPU time offsets (max wait %d nsec)", timeout)

	nsamples := 0
	samples := make([]int64, ncpu)
	timeoutAt := sys.CurrentMonotonicRaw() + int64(timeout)
	for nsamples < ncpu {
		now := sys.CurrentMonotonicRaw()
		if now >= timeoutAt {
			return 0, 0, nil, errors.New("Timeout while reading clock offset samples")
		}
		n, err := unix.Poll(pollfds, int((timeoutAt-now)/int64(time.Millisecond)))
		if err != nil && err != unix.EINTR {
			return 0, 0, nil, err
		}
		if n == 0 {
			continue
		}
		if firstTime == 0 {
			firstTime = sys.CurrentMonotonicRaw()
		}

		for cpu, p := range pollfds {
			if p.Revents&unix.POLLIN != unix.POLLIN {
				continue
			}

			rbs[cpu].read(func(data []byte) {
				r := bytes.NewReader(data)
				s := Sample{}
				err := s.read(r, &referenceEventAttr, nil)
				if err == nil {
					samples[cpu] = int64(s.Time)
					nsamples++
				}
			})

			if samples[cpu] != 0 {
				pollfds[cpu].Events &= ^unix.POLLIN
			}
		}
	}

	return startTime, firstTime, samples, nil
}

func calculateTimeOffsets(procfs proc.FileSystem) error {
	ncpu := procfs.HostFileSystem().NumCPU()
	timeOffsets = make([]int64, ncpu)
	if haveClockID {
		return nil
	}

	// Obtain references samples, one for each CPU.
	startTime, firstTime, samples, err := collectReferenceSamples(ncpu)
	if err != nil {
		return err
	}

	timeBase = startTime
	for cpu, sample := range samples {
		timeOffsets[cpu] = sample - (firstTime - startTime)
		glog.V(2).Infof("EventMonitor CPU %d time offset is %d\n",
			cpu, timeOffsets[cpu])
	}

	return nil
}

func (c *defaultEventSourceController) NewEventSourceLeader(
	attr EventAttr,
	pid, cpu int,
	flags uintptr,
) (EventSourceLeader, error) {
	var err error
	s := &defaultEventSourceLeader{
		pid:        pid,
		cpu:        cpu,
		flags:      flags,
		controller: c,
	}

	if haveClockID {
		attr.UseClockID = true
		attr.ClockID = unix.CLOCK_MONOTONIC_RAW
	} else {
		attr.UseClockID = false
		attr.ClockID = 0
	}
	if s.fd, err = perfEventOpen(attr, pid, cpu, -1, flags); err != nil {
		return nil, err
	}

	if s.streamID, err = unix.IoctlGetInt(s.fd, PERF_EVENT_IOC_ID); err != nil {
		s.Close()
		return nil, err
	}

	if s.rb, err = newRingBuffer(s.fd, c.ringBufferNumPages); err != nil {
		s.Close()
		return nil, err
	}

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(s.fd),
	}
	if err = unix.EpollCtl(c.epollFD, unix.EPOLL_CTL_ADD, s.fd, &event); err != nil {
		s.Close()
		return nil, err
	}

	atomic.AddInt64(&c.leaderCount, 1)
	return s, nil
}

func (c *defaultEventSourceController) Close() {
	if c.pipe[1] != -1 {
		unix.Close(c.pipe[1])
		c.pipe[1] = -1
	}
	if c.pipe[0] != -1 {
		unix.Close(c.pipe[0])
		c.pipe[0] = -1
	}
	if c.epollFD != -1 {
		unix.Close(c.epollFD)
		c.epollFD = -1
	}
}

func (c *defaultEventSourceController) Wait(timeoutAt int64) error {
	defer func() {
		// Drain anything waiting pending in the pipe
		for {
			buffer := make([]byte, 64)
			if _, err := unix.Read(c.pipe[0], buffer); err == unix.EAGAIN {
				break
			}
		}
	}()

	events := make([]unix.EpollEvent, c.leaderCount)
	for {
		var timeout int
		if timeoutAt < 0 {
			timeout = -1
		} else if timeoutAt > 0 {
			if now := sys.CurrentMonotonicRaw(); timeoutAt > now {
				timeout = int((timeoutAt - now) / 1e6)
			} else {
				timeout = 0
			}
		}

		n, err := unix.EpollWait(c.epollFD, events, timeout)
		if err != nil {
			if err != unix.EINTR {
				return err
			}
			continue
		}
		if n == 0 {
			return unix.ETIMEDOUT
		}

		ringBuffersReady := false
		for i := 0; i < n; i++ {
			e := events[i]
			if e.Fd == -1 {
				if e.Events & ^uint32(unix.EPOLLIN) != 0 {
					return unix.ECANCELED
				}
				if e.Events&unix.EPOLLIN != unix.EPOLLIN {
					continue
				}
				fd := c.pipe[0]
				for {
					buffer := make([]byte, 8)
					_, err := unix.Read(fd, buffer)
					if err != nil {
						if err == unix.EAGAIN {
							break
						}
						if err != unix.EINTR {
							return err
						}
						continue
					}
					v := int64(binary.LittleEndian.Uint64(buffer))
					if timeoutAt < 0 || v < timeoutAt {
						timeoutAt = v
					}
				}
			} else if e.Events&unix.EPOLLIN != 0 {
				ringBuffersReady = true
			}
		}
		if ringBuffersReady {
			return nil
		}
	}
}

func (c *defaultEventSourceController) SetTimeoutAt(timeoutAt int64) error {
	buffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(buffer, uint64(timeoutAt))
	for {
		_, err := unix.Write(c.pipe[1], buffer)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		return err
	}
}

type ringBuffer struct {
	fd       int
	memory   []byte
	metadata *metadata
	data     []byte
}

func newRingBuffer(fd int, pageCount int) (*ringBuffer, error) {
	if pageCount <= 0 {
		pageCount = 8
	}
	pageSize := os.Getpagesize()

	memory, err := unix.Mmap(fd, 0, (pageCount+1)*pageSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}

	rb := &ringBuffer{
		fd:       fd,
		memory:   memory,
		metadata: (*metadata)(unsafe.Pointer(&memory[0])),
		data:     memory[pageSize:],
	}

	for {
		seq := atomic.LoadUint32(&rb.metadata.Lock)
		if seq%2 != 0 {
			// seqlock must be even before value is read
			continue
		}

		version := atomic.LoadUint32(&rb.metadata.Version)
		compatVersion := atomic.LoadUint32(&rb.metadata.CompatVersion)

		if atomic.LoadUint32(&rb.metadata.Lock) != seq {
			// seqlock must be even and the same after values have been read
			continue
		}

		if version != 0 || compatVersion != 0 {
			return nil, errors.New("Incompatible ring buffer memory layout version")
		}

		break
	}

	return rb, nil
}

func (rb *ringBuffer) unmap() error {
	return unix.Munmap(rb.memory)
}

// Read calls the given function on each available record in the ringbuffer
func (rb *ringBuffer) read(f func([]byte)) {
	var dataHead, dataTail uint64

	dataTail = rb.metadata.DataTail
	dataHead = atomic.LoadUint64(&rb.metadata.DataHead)

	for dataTail < dataHead {
		dataBegin := dataTail % uint64(len(rb.data))
		dataEnd := dataHead % uint64(len(rb.data))

		var data []byte
		if dataEnd >= dataBegin {
			data = rb.data[dataBegin:dataEnd]
		} else {
			data = rb.data[dataBegin:]
			data = append(data, rb.data[:dataEnd]...)
		}

		f(data)

		//
		// Write dataHead to dataTail to let kernel know that we've
		// consumed the data up to it.
		//
		dataTail = dataHead
		atomic.StoreUint64(&rb.metadata.DataTail, dataTail)

		// Update dataHead in case it has been advanced in the interim
		dataHead = atomic.LoadUint64(&rb.metadata.DataHead)
	}
}
