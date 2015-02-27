package libcontainer

import (
	"fmt"
	"io"
	"os"
)

type processOperations interface {
	wait() (*os.ProcessState, error)
	signal(sig os.Signal) error
	pid() int
}

// Process specifies the configuration and IO for a process inside
// a container.
type Process struct {
	// The command to be run followed by any arguments.
	Args []string

	// Env specifies the environment variables for the process.
	Env []string

	// User will set the uid and gid of the executing process running inside the container
	// local to the contaienr's user and group configuration.
	User string

	// Cwd will change the processes current working directory inside the container's rootfs.
	Cwd string

	// Stdin is a pointer to a reader which provides the standard input stream.
	Stdin io.Reader

	// Stdout is a pointer to a writer which receives the standard output stream.
	Stdout io.Writer

	// Stderr is a pointer to a writer which receives the standard error stream.
	Stderr io.Writer

	// consolePath is the path to the console allocated to the container.
	consolePath string

	ops processOperations
}

// Wait waits for the process to exit.
// Wait releases any resources associated with the Process
func (p Process) Wait() (*os.ProcessState, error) {
	if p.ops == nil {
		return nil, newGenericError(fmt.Errorf("invalid process"), ProcessNotExecuted)
	}
	return p.ops.wait()
}

// Pid returns the process ID
func (p Process) Pid() (int, error) {
	if p.ops == nil {
		return -1, newGenericError(fmt.Errorf("invalid process"), ProcessNotExecuted)
	}
	return p.ops.pid(), nil
}

// Signal sends a signal to the Process.
func (p Process) Signal(sig os.Signal) error {
	if p.ops == nil {
		return newGenericError(fmt.Errorf("invalid process"), ProcessNotExecuted)
	}
	return p.ops.signal(sig)
}

// NewConsole creates new console for process and returns it
func (p *Process) NewConsole(rootuid int) (Console, error) {
	console, err := newConsole(rootuid, rootuid)
	if err != nil {
		return nil, err
	}
	p.consolePath = console.Path()
	return console, nil
}
