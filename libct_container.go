// +build linux

package libcontainer

import (
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"

	_libct "github.com/xemul/libct/go"
	"github.com/docker/libcontainer/libct"
	"github.com/docker/libcontainer/mount"
	"github.com/docker/libcontainer/network"
	"github.com/docker/libcontainer/security/capabilities"
)

// this is to enforce that the libctContainer conforms to the Container interface at compile time
var _ Container = (*libctContainer)(nil)

// libctContainer represents a container that can be executed on linux based host machines
type libctContainer struct {
	mux sync.Mutex

	// path to the containers state directory
	path string

	// initial (immutable) config for the container
	config *Config

	// containers state for the lifetime of the container
	state *State

	// a map of commands in the order which they were created
	processes map[int]*Process

	logger *log.Logger

	ct *_libct.Container
}

func newLibctContainer(config *Config, state *State, logger *log.Logger, ct *_libct.Container) *libctContainer {
	return &libctContainer{
		config:    config,
		state:     state,
		logger:    logger,
		processes: make(map[int]*Process),
		ct: ct,
	}
}

// Path returns the path to the container's directory containing the state
func (c *libctContainer) Path() string {
	return c.path
}

// Config returns the initial configuration for the container that was used
// during initializtion of the container
func (c *libctContainer) Config() *Config {
	return c.config
}

// Status returns the containers current status
func (c *libctContainer) Status() Status {
	return c.state.Status
}

// Stats returns the container's statistics for various cgroup subsystems
func (c *libctContainer) Stats() (*ContainerStats, error) {
	c.logger.Printf("reading stats for container: %s\n", c.path)

	panic("not implemented")
}

// Start runs a new process in the container
func (c *libctContainer) Start(process *Process) (pid int, exitChan chan int, err error) {
	c.logger.Printf("starting new process in container: %s\n", c.path)

	panic("not implemented")
}

// Destroy kills all running process inside the container and cleans up any
// state left on the filesystem
func (c *libctContainer) Destroy() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err := c.ct.Kill(); err != nil {
		return err
	}

	c.logger.Printf("destroying container: %s\n", c.path)

	c.state.Status = Destroyed

	return nil
}

// Processes return the PIDs for processes running inside the container
func (c *libctContainer) Processes() ([]int, error) {
	panic("not implemented")
}

// Pause pauses all processes inside the container
func (c *libctContainer) Pause() error {
	panic("not implemented")
}

// Resume unpause all processes inside the container
func (c *libctContainer) Resume() error {
	panic("not implemented")
}

// changeStatus changes the container's current status to s
// if the state change is not allowed a StateError is returned
//
// This method depends on the caller to hold any locks related to the
// container's state
func (c *libctContainer) changeStatus(s Status) error {

	c.logger.Printf("container %s changing status from %s to %s\n", c.path, c.state.Status, s)

	c.state.Status = s

	return nil
}

// getEnabledCapabilities returns the capabilities that should not be dropped by the container.
func getEnabledCapabilities(capList []string) uint64 {
	var keep uint64 = 0
	for _, capability := range capList {
		if c := capabilities.GetCapability(capability); c != nil {
			keep |= uint64(c.Value)
		}
	}
	return keep
}

func dropBoundingSet(ct *_libct.Container, capabilities []string) error {
	caps := getEnabledCapabilities(capabilities)

	if err := ct.SetCaps(caps, _libct.CAPS_BSET); err != nil {
		return err
	}

	return nil
}

func (c *libctContainer) startInitProcess(process *Process) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	process.exitChan = make(chan int, 1)

	// because this is our init process we can alwasy set it to 1
	c.processes[1] = process

	c.logger.Printf("container %s starting init process\n", c.path)
	if err:= c.ct.SetParentDeathSignal(syscall.SIGKILL); err != nil {
		return err
	}

	if err:= dropBoundingSet(c.ct, c.config.Capabilities); err != nil {
		return err
	}

	err := c.ct.SetNsMask(uint64(getNamespaceFlags(c.config.Namespaces)))
	if err != nil {
		return err
	}

	if err := libct.InitializeMountNamespace(c.ct, c.config.Rootfs, process.ConsolePath,
		(*mount.MountConfig)(c.config.MountConfig)); err != nil {

		return err
	}

	if err := c.setupNetwork(); err != nil {
		return fmt.Errorf("setup networking %s", err)
	}

	var fds *[3]uintptr
	if process.ConsolePath != "" {
		ttyfd, err := os.OpenFile(process.ConsolePath, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		fds = &[3]uintptr{ttyfd.Fd(), ttyfd.Fd(), ttyfd.Fd()}

		err = c.ct.SetConsoleFd(ttyfd)
		if err != nil {
			return err
		}
	} // FIXME proxy pipes

	pid, err := c.ct.SpawnExecve(process.Args[0], process.Args, process.Env, fds)
	if err != nil {
		return err
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	process.cmd.Process = p

	process.pipe.CloseChild()

	startTime, err := process.startTime()
	if err != nil {
		process.kill()

		return err
	}

	// update state
	c.state.InitPid = process.pid()
	c.state.InitStartTime = startTime

	c.logger.Printf("container %s init process started at %s with pid %d\n", c.path, c.state.InitStartTime, c.state.InitPid)

	if err := c.changeStatus(Running); err != nil {
		process.kill()

		return err
	}

	c.logger.Printf("container %s waiting on init process\n", c.path)

	// finally the users' process should be running inside the container and we did not encounter
	// any errors during the init of the namespace.  we can now wait on the process and return
	go func() {
		process.wait()
		c.ct.Wait()
	}()

	return nil
}

func (c *libctContainer) setupNetwork() error {
	for _, config := range c.config.Networks {
		c.logger.Printf("container %s creating network for %s\n", c.path, config.Type)

		strategy, err := libct.GetStrategy(config.Type)
		if err != nil {
			return err
		}

		err = strategy.Create(c.ct, (*network.Network)(config), &c.state.NetworkState)
		if err != nil {
			return err
		}
	}

	return nil
}
