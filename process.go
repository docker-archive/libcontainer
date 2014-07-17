package libcontainer

import (
	"io"
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
	Args []string

	// Map of environment variables to their values.
	Env []string

	// Stdin is a pointer to a reader which provides the standard input stream.
	// Stdout is a pointer to a writer which receives the standard output stream.
	// Stderr is a pointer to a writer which receives the standard error stream.
	//
	// If a reader or writer is nil, the input stream is assumed to be empty and the output is
	// discarded.
	//
	// Stdout and Stderr may refer to the same writer in which case the output is interspersed.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// ExtraFiles are used to pass fds to the container's process
	ExtraFiles []*os.File

	// Master is the pty master file for the process
	Master *os.File

	// ConsolePath is the path to the pty slave for use by the master
	ConsolePath string

	cmd *exec.Cmd

	pipe *syncpipe.SyncPipe

	exitChan chan int
}

func (p *ProcessConfig) ExitChan() chan int {
	return p.exitChan
}

// createCommand will create the *exec.Cmd with the provided path to libcontainer's init binary
// that sets up the container inside the namespaces based on the config
func (p *ProcessConfig) createCommand(initPath string, config *Config, pipe *syncpipe.SyncPipe) error {
	if p.cmd != nil {
		return ErrProcessCommandExists
	}

	p.cmd = exec.Command(initPath, p.Args...)
	p.pipe = pipe

	if !config.Tty {
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

// allocatePty will create a new pty master and slave pair
func (p *ProcessConfig) allocatePty() error {
	master, console, err := console.CreateMasterAndConsole()
	if err != nil {
		return err
	}

	p.Master = master
	p.ConsolePath = console

	return nil
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
