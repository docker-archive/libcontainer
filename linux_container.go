// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"syscall"

	"github.com/docker/libcontainer/apparmor"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/cgroups/fs"
	"github.com/docker/libcontainer/cgroups/systemd"
	"github.com/docker/libcontainer/label"
	"github.com/docker/libcontainer/mount"
	"github.com/docker/libcontainer/netlink"
	"github.com/docker/libcontainer/network"
	"github.com/docker/libcontainer/security/restrict"
	"github.com/docker/libcontainer/system"
)

// this is to enforce that the linuxContainer conforms to the Container interface at compile time
var _ Container = (*linuxContainer)(nil)

// linuxContainer represents a container that can be executed on linux based host machines
type linuxContainer struct {
	mux sync.Mutex

	// path to the containers state directory
	path string

	// initial (immutable) config for the container
	config *Config

	// containers state for the lifetime of the container
	state *State

	// a map of commands in the order which they were created
	processes map[int]*Process

	// active cgroup to cleanup
	activeCgroup cgroups.ActiveCgroup

	logger *log.Logger
}

func newLinuxContainer(config *Config, state *State, logger *log.Logger) *linuxContainer {
	return &linuxContainer{
		config:    config,
		state:     state,
		logger:    logger,
		processes: make(map[int]*Process),
	}
}

// Path returns the path to the container's directory containing the state
func (c *linuxContainer) Path() string {
	return c.path
}

// Config returns the initial configuration for the container that was used
// during initializtion of the container
func (c *linuxContainer) Config() *Config {
	return c.config
}

// Status returns the containers current status
func (c *linuxContainer) Status() Status {
	return c.state.Status
}

// Stats returns the container's statistics for various cgroup subsystems
func (c *linuxContainer) Stats() (*ContainerStats, error) {
	var (
		err            error
		containerStats = &ContainerStats{}
	)

	c.logger.Printf("reading stats for container: %s\n", c.path)

	if containerStats.CgroupStats, err = fs.GetStats(c.config.Cgroups); err != nil {
		return containerStats, err
	}

	if containerStats.NetworkStats, err = network.GetStats(&c.state.NetworkState); err != nil {
		return containerStats, err
	}

	return containerStats, nil
}

// Start runs a new process in the container
func (c *linuxContainer) Start(process *Process) (pid int, exitChan chan int, err error) {
	c.logger.Printf("starting new process in container: %s\n", c.path)

	panic("not implemented")
}

// Destroy kills all running process inside the container and cleans up any
// state left on the filesystem
func (c *linuxContainer) Destroy() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.logger.Printf("destroying container: %s\n", c.path)

	c.state.Status = Destroyed

	return c.activeCgroup.Cleanup()
}

// Processes return the PIDs for processes running inside the container
func (c *linuxContainer) Processes() ([]int, error) {
	panic("not implemented")
}

// Pause pauses all processes inside the container
func (c *linuxContainer) Pause() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err := c.changeStatus(Pausing); err != nil {
		return err
	}

	if err := c.toggleCgroupFreezer(cgroups.Frozen); err != nil {
		return err
	}

	if err := c.changeStatus(Paused); err != nil {
		return err
	}

	return nil
}

// Resume unpause all processes inside the container
func (c *linuxContainer) Resume() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err := c.changeStatus(Resuming); err != nil {
		return err
	}

	if err := c.toggleCgroupFreezer(cgroups.Thawed); err != nil {
		return err
	}

	if err := c.changeStatus(Running); err != nil {
		return err
	}

	return nil
}

// changeStatus changes the container's current status to s
// if the state change is not allowed a StateError is returned
//
// This method depends on the caller to hold any locks related to the
// container's state
func (c *linuxContainer) changeStatus(s Status) error {

	c.logger.Printf("container %s changing status from %s to %s\n", c.path, c.state.Status, s)

	c.state.Status = s

	return nil
}

func (c *linuxContainer) toggleCgroupFreezer(state cgroups.FreezerState) (err error) {
	if systemd.UseSystemd() {
		c.logger.Printf("container %s modifying freezer state to %s with systemd\n", c.path, state)

		err = systemd.Freeze(c.config.Cgroups, state)
	} else {
		c.logger.Printf("container %s modifying freezer state to %s with fs\n", c.path, state)

		err = fs.Freeze(c.config.Cgroups, state)
	}

	return err
}

func (c *linuxContainer) startInitProcess(process *Process) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	process.exitChan = make(chan int, 1)

	// because this is our init process we can alwasy set it to 1
	c.processes[1] = process

	c.logger.Printf("container %s starting init process\n", c.path)

	if err := process.cmd.Start(); err != nil {
		return err
	}

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

	// Do this before syncing with child so that no children can escape the cgroup
	if err := c.applyCgroups(process); err != nil {
		process.kill()

		return err
	}

	// networking initailiztion needs to happen after we have a running process so we can have the pid of
	// namespaced process to move veths or other network requirements into the namespace
	if err := c.createNetworks(process); err != nil {
		process.kill()

		return err
	}

	// now that the setup in the parent is complete lets send our state to our child process
	// so that it can complete setup of the namespace
	initState := &initState{
		Config:  c.config,
		State:   c.state,
		Process: process,
	}

	stateData, err := json.Marshal(initState)
	if err != nil {
		return err
	}

	c.logger.Printf("container %s sending init state to child\n", c.path)

	if err := process.pipe.SendToChild(stateData); err != nil {
		process.kill()

		return err
	}

	// finally we need to wait on the child to finish setup of the namespace before it will
	// exec the users app
	if err := process.pipe.ErrorsFromChild(); err != nil {
		c.logger.Printf("container %s received error from child process: %q\n", err)

		process.kill()

		return err
	}

	if err := c.changeStatus(Running); err != nil {
		process.kill()

		return err
	}

	c.logger.Printf("container %s waiting on init process\n", c.path)

	// finally the users' process should be running inside the container and we did not encounter
	// any errors during the init of the namespace.  we can now wait on the process and return
	go process.wait()

	return nil
}

// applyCgroups places the process into the correct container cgroups
func (c *linuxContainer) applyCgroups(process *Process) error {
	var (
		err          error
		active       cgroups.ActiveCgroup
		cgroupConfig = c.config.Cgroups
	)

	if cgroupConfig != nil {
		if systemd.UseSystemd() {
			c.logger.Printf("container %s placing pid %d into cgroups with systemd\n", c.path, process.pid())

			active, err = systemd.Apply(cgroupConfig, process.pid())
		} else {
			c.logger.Printf("container %s placing pid %d into cgroups with fs\n", c.path, process.pid())

			active, err = fs.Apply(cgroupConfig, process.pid())
		}
	}

	if err != nil {
		return err
	}

	c.activeCgroup = active

	return nil
}

func (c *linuxContainer) createNetworks(process *Process) error {
	for _, config := range c.config.Networks {
		c.logger.Printf("container %s creating network for %s\n", c.path, config.Type)

		strategy, err := network.GetStrategy(config.Type)
		if err != nil {
			return err
		}

		if err := strategy.Create((*network.Network)(config), process.pid(), &c.state.NetworkState); err != nil {
			return err
		}
	}

	return nil
}

// initializeNamespace is called by libcontainer's init process for the container and runs
// setup in the newly created namespace
func (c *linuxContainer) initializeNamespace(process *Process) (err error) {
	if c.state.Status != Init {
		return fmt.Errorf("initializeNamespace can only be called when container state is Init")
	}

	if err := replaceEnvironment(process); err != nil {
		return err
	}

	if err := process.openConsole(); err != nil {
		return fmt.Errorf("open console %s", err)
	}

	if _, err := syscall.Setsid(); err != nil {
		return fmt.Errorf("setsid %s", err)
	}

	if process.ConsolePath != "" {
		c.logger.Printf("container %s setup console %s\n", c.path, process.ConsolePath)

		if err := system.Setctty(); err != nil {
			return fmt.Errorf("setctty %s", err)
		}
	}

	if err := c.setupNetwork(); err != nil {
		return fmt.Errorf("setup networking %s", err)
	}

	if err := c.setupRoute(); err != nil {
		return fmt.Errorf("setup route %s", err)
	}

	c.logger.Printf("container %s initializing mount namespace in %s\n", c.path, c.config.Rootfs)

	if err := mount.InitializeMountNamespace(c.config.Rootfs, process.ConsolePath,
		(*mount.MountConfig)(c.config.MountConfig)); err != nil {

		return fmt.Errorf("setup mount namespace %s", err)
	}

	if c.config.Hostname != "" {
		c.logger.Printf("container %s setting hostname %q\n", c.path, c.config.Hostname)

		if err := syscall.Sethostname([]byte(c.config.Hostname)); err != nil {
			return fmt.Errorf("sethostname %s", err)
		}
	}

	if c.config.AppArmorProfile != "" {
		c.logger.Printf("container %s setting apparmor profile to %q\n", c.path, c.config.AppArmorProfile)

		if err := apparmor.ApplyProfile(c.config.AppArmorProfile); err != nil {
			return fmt.Errorf("set apparmor profile %s: %s", c.config.AppArmorProfile, err)
		}
	}

	if c.config.ProcessLabel != "" {
		c.logger.Printf("container %s setting process label to %q\n", c.path, c.config.ProcessLabel)

		if err := label.SetProcessLabel(c.config.ProcessLabel); err != nil {
			return fmt.Errorf("set process label %s", err)
		}
	}

	// TODO: (crosbymichael) make this configurable at the Config level
	if c.config.RestrictSys {
		c.logger.Printf("container %s restricting proc and sys filesystems\n", c.path)

		if err := restrict.Restrict("proc/sys", "proc/sysrq-trigger", "proc/irq", "proc/bus", "sys"); err != nil {
			return err
		}
	}

	pdeathSignal, err := system.GetParentDeathSignal()
	if err != nil {
		return fmt.Errorf("get parent death signal %s", err)
	}

	if err := finalizeNamespace(c.config); err != nil {
		return fmt.Errorf("finalize namespace %s", err)
	}

	// FinalizeNamespace can change user/group which clears the parent death
	// signal, so we restore it here.
	if err := restoreParentDeathSignal(pdeathSignal); err != nil {
		return fmt.Errorf("restore parent death signal %s", err)
	}

	c.logger.Printf("container %s execing users process\n", c.path)

	return process.execv()
}

// setupNetwork uses the Network config if it is not nil to initialize
// the new veth interface inside the container for use by changing the name to eth0
// setting the MTU and IP address along with the default gateway
func (c *linuxContainer) setupNetwork() error {
	for _, config := range c.config.Networks {
		c.logger.Printf("container %s initialzing network for %s\n", c.path, config.Type)

		strategy, err := network.GetStrategy(config.Type)
		if err != nil {
			return err
		}

		if err := strategy.Initialize((*network.Network)(config), &c.state.NetworkState); err != nil {
			return err
		}
	}

	return nil
}

func (c *linuxContainer) setupRoute() error {
	for _, config := range c.config.Routes {
		c.logger.Printf("container %s setting up route for %s\n", c.path, config.InterfaceName)

		if err := netlink.AddRoute(config.Destination, config.Source, config.Gateway, config.InterfaceName); err != nil {
			return err
		}
	}

	return nil
}
