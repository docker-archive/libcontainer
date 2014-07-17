package libcontainer

import (
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/docker/libcontainer/console"
	"github.com/docker/libcontainer/syncpipe"
	"github.com/docker/libcontainer/system"
)

// Configuration for a process to be run inside a container.
type ProcessConfig struct {
	// The command to be run followed by any arguments.
	Args []string `json:"args,omitempty"`

	// Map of environment variables to their values.
	Env []string `json:"environment,omitempty"`

	// Stdin is a pointer to a reader which provides the standard input stream.
	// Stdout is a pointer to a writer which receives the standard output stream.
	// Stderr is a pointer to a writer which receives the standard error stream.
	//
	// If a reader or writer is nil, the input stream is assumed to be empty and the output is
	// discarded.
	//
	// Stdout and Stderr may refer to the same writer in which case the output is interspersed.
	Stdin  io.Reader `json:"-"`
	Stdout io.Writer `json:"-"`
	Stderr io.Writer `json:"-"`

	// ExtraFiles are used to pass fds to the container's process
	ExtraFiles []*os.File `json:"-"`

	// master is the pty master file for the process
	Master *os.File `json:"-"`

	// consolePath is the path to the pty slave for use by the master
	ConsolePath string `json:"console_path,omitempty"`

	cmd *exec.Cmd

	pipe *syncpipe.SyncPipe

	exitChan chan int
}

func (p *ProcessConfig) ExitChan() chan int {
	return p.exitChan
}

// createCommand will create the *exec.Cmd with the provided path to libcontainer's init binary
// that sets up the container inside the namespaces based on the config
func (p *ProcessConfig) createCommand(initArgs []string, config *Config, pipe *syncpipe.SyncPipe) error {
	if p.cmd != nil {
		return ErrProcessCommandExists
	}

	p.cmd = exec.Command(initArgs[0], append(initArgs[1:], p.Args...)...)
	log.Println(p.cmd.Path, p.cmd.Args)
	p.pipe = pipe

	if p.ConsolePath == "" {
		// Note: these are only used in non-tty mode
		// if there is a tty for the container it will be opened within the namespace and the
		// fds will be duped to stdin, stdiout, and stderr
		p.cmd.Stdin = p.Stdin
		p.cmd.Stdout = p.Stdout
		p.cmd.Stderr = p.Stderr
	}

	p.cmd.Env = p.Env
	p.cmd.Dir = config.Rootfs

	// Take any extra files from the caller and ensure that our syncpipe was passed
	p.cmd.ExtraFiles = append(p.ExtraFiles, pipe.Child())

	if p.cmd.SysProcAttr == nil {
		p.cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	p.cmd.SysProcAttr.Cloneflags = uintptr(getNamespaceFlags(config.Namespaces))
	p.cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL

	return nil
}

// AllocatePty will create a new pty master and slave pair
func (p *ProcessConfig) AllocatePty() (*os.File, error) {
	master, console, err := console.CreateMasterAndConsole()
	if err != nil {
		return nil, err
	}

	p.Master = master
	p.ConsolePath = console

	return master, nil
}

func (p *ProcessConfig) Signal(sig os.Signal) error {
	return p.cmd.Process.Signal(sig)
}

// Wait waits for the process to die then returns the exit status
func (p *ProcessConfig) Wait() int {
	return <-p.exitChan
}

// startTime returns the processes start time
func (p *ProcessConfig) startTime() (string, error) {
	return system.GetProcessStartTime(p.cmd.Process.Pid)
}

func (p *ProcessConfig) pid() int {
	return p.cmd.Process.Pid
}

func (p *ProcessConfig) kill() {
	p.cmd.Process.Kill()
	p.cmd.Wait()
}

func (p *ProcessConfig) close() error {
	err := p.pipe.Close()

	if p.Master != nil {
		if merr := p.Master.Close(); err == nil {
			err = merr
		}
	}

	return err
}

func (p *ProcessConfig) openConsole() error {
	if p.ConsolePath != "" {
		return console.OpenAndDup(p.ConsolePath)
	}

	return nil
}

func (p *ProcessConfig) execv() error {
	return system.Execv(p.Args[0], p.Args[0:], p.Env)
}

func (p *ProcessConfig) wait() {
	if err := p.cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			// TODO: unexpected error from wait
		}
	}

	p.close()

	p.exitChan <- p.cmd.ProcessState.Sys().(syscall.WaitStatus).ExitStatus()

	close(p.exitChan)
}
