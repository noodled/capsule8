package subscription

import (
	"fmt"
	"strings"
	"syscall"

	api "github.com/capsule8/api/v0"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/golang/glog"
	"golang.org/x/sys/unix"
)

const (
	exitSymbol    = "do_exit"
	exitFetchargs = "code=%di:s64"
)

func decodeSchedProcessFork(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	childPid := data["child_pid"].(int32)
	childID := processID(int(childPid))

	ev := newEventFromSample(sample, data)
	ev.Event = &api.Event_Process{
		Process: &api.ProcessEvent{
			Type:         api.ProcessEventType_PROCESS_EVENT_TYPE_FORK,
			ForkChildPid: childPid,
			ForkChildId:  childID,
		},
	}

	return ev, nil
}

func decodeSchedProcessExec(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	//
	// Grab command line out of procfs ASAP
	//
	hostPid := data["common_pid"].(int32)
	filename := data["filename"].(string)
	commandLine := sys.HostProcFS().CommandLine(int(hostPid))

	ev := newEventFromSample(sample, data)
	processEvent := &api.ProcessEvent{
		Type:            api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
		ExecFilename:    filename,
		ExecCommandLine: commandLine,
	}

	ev.Event = &api.Event_Process{
		Process: processEvent,
	}

	return ev, nil
}

func decodeDoExit(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	var exitStatus int
	var exitSignal syscall.Signal
	var coreDumped bool

	// The kprobe fetches the argument 'long code' as an s64. It's
	// the same value returned as a status via waitpid(2).
	code := data["code"].(int64)

	ws := unix.WaitStatus(code)
	if ws.Exited() {
		exitStatus = ws.ExitStatus()
	} else if ws.Signaled() {
		exitSignal = ws.Signal()
		coreDumped = ws.CoreDump()
	}

	ev := newEventFromSample(sample, data)
	ev.Event = &api.Event_Process{
		Process: &api.ProcessEvent{
			Type:           api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
			ExitCode:       int32(code),
			ExitStatus:     uint32(exitStatus),
			ExitSignal:     uint32(exitSignal),
			ExitCoreDumped: coreDumped,
		},
	}

	return ev, nil
}

type processForkFilter struct {
}

func (pef *processForkFilter) String() string {
	return ""
}

type processExecFilter struct {
	filename        string
	filenamePattern string
}

func (pef *processExecFilter) String() string {
	//
	// Equality takes precedence since it's better performance
	//
	if len(pef.filename) > 0 {
		return fmt.Sprintf("filename == %s", pef.filename)
	}

	if len(pef.filenamePattern) > 0 {
		return fmt.Sprintf("filename ~ %s", pef.filenamePattern)
	}

	return ""
}

type processExitFilter struct {
	exitCode string
}

func (pef *processExitFilter) String() string {
	if len(pef.exitCode) > 0 {
		return fmt.Sprintf("code == %s", pef.exitCode)
	}

	return ""
}

type processFilterSet struct {
	fork []processForkFilter
	exec []processExecFilter
	exit []processExitFilter
}

func (pes *processFilterSet) add(pef *api.ProcessEventFilter) {
	if pef.Type == api.ProcessEventType_PROCESS_EVENT_TYPE_FORK {
		f := processForkFilter{}
		pes.fork = append(pes.fork, f)
	} else if pef.Type == api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC {
		f := processExecFilter{}

		if pef.ExecFilename != nil {
			f.filename = pef.ExecFilename.Value
		}

		if pef.ExecFilenamePattern != nil {
			f.filenamePattern = pef.ExecFilenamePattern.Value
		}

		pes.exec = append(pes.exec, f)
	} else if pef.Type == api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT {
		f := processExitFilter{}

		if pef.ExitCode != nil {
			f.exitCode = fmt.Sprintf("%d", pef.ExitCode.Value)
		}

		pes.exit = append(pes.exit, f)
	}
}

func (pes *processFilterSet) len() int {
	return len(pes.fork) + len(pes.exec) + len(pes.exit)
}

func (pes *processFilterSet) registerEvents(monitor *perf.EventMonitor) {
	glog.V(2).Infof("registering events for pes %+v", pes)

	if pes.fork != nil {
		var parts []string

		for _, f := range pes.fork {
			s := f.String()
			if len(s) > 0 {
				parts = append(parts, fmt.Sprintf("(%s)", f))
			}
		}

		filter := strings.Join(parts, " || ")

		eventName := "sched/sched_process_fork"
		err := monitor.RegisterEvent(eventName, decodeSchedProcessFork,
			filter, nil)

		if err != nil {
			glog.Infof("Couldn't get %s event id: %v",
				eventName, err)
		}
	}

	if pes.exec != nil {
		var parts []string

		for _, f := range pes.exec {
			s := f.String()
			if len(s) > 0 {
				parts = append(parts, fmt.Sprintf("(%s)", s))
			}
		}

		filter := strings.Join(parts, " || ")

		eventName := "sched/sched_process_exec"
		err := monitor.RegisterEvent(eventName, decodeSchedProcessExec,
			filter, nil)
		if err != nil {
			glog.Infof("Couldn't get %s event id: %v",
				eventName, err)
		}
	}

	if pes.exit != nil {
		var parts []string

		for _, f := range pes.exit {
			s := f.String()
			if len(s) > 0 {
				parts = append(parts, fmt.Sprintf("(%s)", s))
			}
		}

		filter := strings.Join(parts, " || ")

		name := perf.UniqueProbeName("capsule8", "do_exit")
		_, err := monitor.RegisterKprobe(name, exitSymbol,
			false, exitFetchargs, decodeDoExit, filter, nil)
		if err != nil {
			glog.Errorf("Couldn't register kprobe for %s: %s",
				exitSymbol, err)
		}
	}
}