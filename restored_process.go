// +build linux

package libcontainer

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/docker/libcontainer/system"
)

func newRestoredProcess(pidfile string) (*restoredProcess, error) {
	var (
		data []byte
		err  error
	)
	data, err = ioutil.ReadFile(pidfile)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty pidfile, restore failed")
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return nil, err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}
	started, err := system.GetProcessStartTime(pid)
	if err != nil {
		return nil, err
	}
	return &restoredProcess{
		proc:             proc,
		processStartTime: started,
	}, nil
}

type restoredProcess struct {
	proc             *os.Process
	processStartTime string
}

func (p *restoredProcess) start() error {
	return newGenericError(fmt.Errorf("restored process cannot be started"), SystemError)
}

func (p *restoredProcess) pid() int {
	return p.proc.Pid
}

func (p *restoredProcess) terminate() error {
	err := p.proc.Kill()
	if _, werr := p.wait(); err == nil {
		err = werr
	}
	return err
}

func (p *restoredProcess) wait() (*os.ProcessState, error) {
	// TODO: how do we wait on the actual process?
	// maybe use --exec-cmd in criu
	st, err := p.proc.Wait()
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (p *restoredProcess) startTime() (string, error) {
	return p.processStartTime, nil
}

func (p *restoredProcess) signal(s os.Signal) error {
	return p.proc.Signal(s)
}

// nonChildProcess represents a process where the calling process is not
// the parent process.  This process is created when a factory loads a container from
// a persisted state.
type nonChildProcess struct {
	processPid       int
	processStartTime string
}

func (p *nonChildProcess) start() error {
	return newGenericError(fmt.Errorf("restored process cannot be started"), SystemError)
}

func (p *nonChildProcess) pid() int {
	return p.processPid
}

func (p *nonChildProcess) terminate() error {
	return newGenericError(fmt.Errorf("restored process cannot be terminated"), SystemError)
}

func (p *nonChildProcess) wait() (*os.ProcessState, error) {
	return nil, newGenericError(fmt.Errorf("restored process cannot be waited on"), SystemError)
}

func (p *nonChildProcess) startTime() (string, error) {
	return p.processStartTime, nil
}

func (p *nonChildProcess) signal(s os.Signal) error {
	return newGenericError(fmt.Errorf("restored process cannot be signaled"), SystemError)
}
