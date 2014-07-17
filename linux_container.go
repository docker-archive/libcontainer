// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
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
	processes map[int]*ProcessConfig

	// active cgroup to cleanup
	activeCgroup cgroups.ActiveCgroup
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

// Start runs a new process in the container
func (c *linuxContainer) Start(process *ProcessConfig) (pid int, exitChan chan int, err error) {
	panic("not implemented")
}

// Destroy kills all running process inside the container and cleans up any
// state left on the filesystem
func (c *linuxContainer) Destroy() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.state.Status = Destroyed

	return c.activeCgroup.Cleanup()
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
	if err := c.applyCgroups(process); err != nil {
		process.kill()

		return err
	}

	// networking initailiztion needs to happen after we have a running process so we can have the pid of
	// namespaced process to move veths or other network requirements into the namespace
	if err := c.initializeNetworking(process); err != nil {
		process.kill()

		return err
	}

	// now that the setup in the parent is complete lets send our state to our child process
	// so that it can complete setup of the namespace
	stateData, err := json.Marshal(c.state)
	if err != nil {
		return err
	}

	if err := process.pipe.SendToChild(stateData); err != nil {
		process.kill()

		return err
	}

	// finally we need to wait on the child to finish setup of the namespace before it will
	// exec the users app
	if err := process.pipe.ErrorsFromChild(); err != nil {
		process.kill()

		return err
	}

	c.state.Status = Running

	// finally the users' process should be running inside the container and we did not encounter
	// any errors during the init of the namespace.  we can now wait on the process and return
	go process.wait()

	return nil
}

// applyCgroups places the process into the correct container cgroups
func (c *linuxContainer) applyCgroups(process *ProcessConfig) error {
	var (
		err          error
		active       cgroups.ActiveCgroup
		cgroupConfig = c.config.Cgroups
	)

	if cgroupConfig != nil {
		if systemd.UseSystemd() {
			active, err = systemd.Apply(cgroupConfig, process.pid())
		}

		active, err = fs.Apply(cgroupConfig, process.pid())
	}

	if err != nil {
		return err
	}

	c.activeCgroup = active

	return nil
}

func (c *linuxContainer) initializeNetworking(process *ProcessConfig) error {
	for _, config := range c.config.Networks {
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
func (c *linuxContainer) initializeNamespace(process *ProcessConfig) (err error) {
	if c.state.Status != Init {
		return fmt.Errorf("initializeNamespace can only be called when container state is Init")
	}

	if err := replaceEnvironment(process.Env); err != nil {
		return err
	}

	if err := process.openConsole(); err != nil {
		return fmt.Errorf("open console %s", err)
	}

	if _, err := syscall.Setsid(); err != nil {
		return fmt.Errorf("setsid %s", err)
	}

	if c.config.Tty {
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

	if err := mount.InitializeMountNamespace(c.config.Rootfs, process.ConsolePath,
		(*mount.MountConfig)(c.config.MountConfig)); err != nil {

		return fmt.Errorf("setup mount namespace %s", err)
	}

	if c.config.Hostname != "" {
		if err := syscall.Sethostname([]byte(c.config.Hostname)); err != nil {
			return fmt.Errorf("sethostname %s", err)
		}
	}

	if err := apparmor.ApplyProfile(c.config.AppArmorProfile); err != nil {
		return fmt.Errorf("set apparmor profile %s: %s", c.config.AppArmorProfile, err)
	}

	if err := label.SetProcessLabel(c.config.ProcessLabel); err != nil {
		return fmt.Errorf("set process label %s", err)
	}

	// TODO: (crosbymichael) make this configurable at the Config level
	if c.config.RestrictSys {
		if err := restrict.Restrict("proc/sys", "proc/sysrq-trigger", "proc/irq", "proc/bus", "sys"); err != nil {
			return err
		}
	}

	pdeathSignal, err := system.GetParentDeathSignal()
	if err != nil {
		return fmt.Errorf("get parent death signal %s", err)
	}

	if err := finalizeNamespace(c); err != nil {
		return fmt.Errorf("finalize namespace %s", err)
	}

	// FinalizeNamespace can change user/group which clears the parent death
	// signal, so we restore it here.
	if err := restoreParentDeathSignal(pdeathSignal); err != nil {
		return fmt.Errorf("restore parent death signal %s", err)
	}

	return process.execv()
}

// setupNetwork uses the Network config if it is not nil to initialize
// the new veth interface inside the container for use by changing the name to eth0
// setting the MTU and IP address along with the default gateway
func (c *linuxContainer) setupNetwork() error {
	for _, config := range c.config.Networks {
		strategy, err := network.GetStrategy(config.Type)
		if err != nil {
			return err
		}

		if err := strategy.Initialize((*network.Network)(config), c.state.NetworkState); err != nil {
			return err
		}
	}

	return nil
}

func (c *linuxContainer) setupRoute() error {
	for _, config := range c.config.Routes {
		if err := netlink.AddRoute(config.Destination, config.Source, config.Gateway, config.InterfaceName); err != nil {
			return err
		}
	}

	return nil
}
