// +build linux

package libcontainer

import (
	"sync"

	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/cgroups/fs"
	"github.com/docker/libcontainer/cgroups/systemd"
	"github.com/docker/libcontainer/network"
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
	processes map[int]*ProcessConfig
}

func newLinuxContainer(path string, config *Config, state *State) *linuxContainer {
	return &linuxContainer{
		path:   path,
		config: config,
		state:  state,
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

	if containerStats.CgroupStats, err = fs.GetStats(c.config.Cgroups); err != nil {
		return containerStats, err
	}

	if containerStats.NetworkStats, err = network.GetStats(&c.state.NetworkState); err != nil {
		return containerStats, err
	}

	return containerStats, nil
}

func (c *linuxContainer) Start(process *ProcessConfig) (pid int, exitChan chan int, err error) {
	panic("not implemented")
}

// Destroy kills all running process inside the container and cleans up any
// state left on the filesystem
func (c *linuxContainer) Destroy() error {
	panic("not implemented")
}

// Processes return the PIDs for processes running inside the container
func (c *linuxContainer) Processes() ([]int, error) {
	panic("not implemented")
}

// Pause pauses all processes inside the container
func (c *linuxContainer) Pause() error {
	return c.toggleCgroupFreezer(cgroups.Frozen)
}

// Resume unpause all processes inside the container
func (c *linuxContainer) Resume() error {
	return c.toggleCgroupFreezer(cgroups.Thawed)
}

func (c *linuxContainer) toggleCgroupFreezer(state cgroups.FreezerState) (err error) {
	c.mux.Lock()
	if systemd.UseSystemd() {
		err = systemd.Freeze(c.config.Cgroups, state)
	} else {
		err = fs.Freeze(c.config.Cgroups, state)
	}
	c.mux.Unlock()

	return err
}

func (c *linuxContainer) startInitProcess(process *ProcessConfig) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	process.exitChan = make(chan int, 1)

	// because this is our init process we can alwasy set it to 1
	c.processes[1] = process

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

	// Do this before syncing with child so that no children can escape the cgroup
	cleaner, err := c.applyCgroups(process)
	if err != nil {
		process.kill()

		return err
	}

	/*
	   TODO: cgroup cleanup can be handled at the container destroy level
	   if cleaner != nil {
	       cleaner.Cleanup()
	   }
	*/

	// networking initailiztion needs to happen after we have a running process so we can have the pid of
	// namespaced process to move veths or other network requirements into the namespace
	if err := c.initializeNetworking(process); err != nil {
		process.kill()

		return err
	}

	// now that the setup in the parent is complete lets send our state to our child process
	// so that it can complete setup of the namespace
	if err := process.pipe.SendState(c.state); err != nil {
		process.kill()

		return err
	}

	// finally we need to wait on the child to finish setup of the namespace before it will
	// exec the users app
	if err := process.pipe.ErrorsFromChildInit(); err != nil {
		process.kill()

		return err
	}

	// finally the users' process should be running inside the container and we did not encounter
	// any errors during the init of the namespace.  we can now wait on the process and return
	go process.wait()

	return nil
}

// applyCgroups places the process into the correct container cgroups
func (c *linuxContainer) applyCgroups(process *ProcessConfig) (cgroups.Cleaner, error) {
	cgroupConfig := c.config.Cgroups
	if cgroupConfig != nil {

		if systemd.UseSystemd() {
			return systemd.Apply(cgroupConfig, process.pid())
		}

		return fs.Apply(cgroupConfig, process.pid())
	}

	return nil, nil
}

func (c *linuxContainer) initializeNetworking(process *ProcessConfig) error {
	for _, config := range container.Networks {

		strategy, err := network.GetStrategy(config.Type)
		if err != nil {
			return err
		}

		if err := strategy.Create((*network.Network)(config), process.pid(), c.state.NetworkState); err != nil {
			return err
		}
	}

	return nil
}
