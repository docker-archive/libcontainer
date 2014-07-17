// +build linux

package libcontainer

import (
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/cgroups/fs"
	"github.com/docker/libcontainer/cgroups/systemd"
	"github.com/docker/libcontainer/network"
)

// this is to enforce that the linuxContainer conforms to the Container interface at compile time
var _ Container = (*linuxContainer)(nil)

// linuxContainer represents a container that can be executed on linux based host machines
type linuxContainer struct {
	// path to the containers state directory
	path string

	// initial (immutable) config for the container
	config *Config

	// containers state for the lifetime of the container
	state *State
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
	if systemd.UseSystemd() {
		err = systemd.Freeze(c.config.Cgroups, state)
	} else {
		err = fs.Freeze(c.config.Cgroups, state)
	}

	return err
}
