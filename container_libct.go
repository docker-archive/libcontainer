// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	log "github.com/Sirupsen/logrus"
	libct "github.com/avagin/libct/go"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/system"
	"github.com/docker/libcontainer/utils"
)

// this is to enforce that the libctContainer conforms to the Container interface at compile time
var _ Container = (*libctContainer)(nil)

// libctContainer represents a container that can be executed on linux based host machines
type libctContainer struct {
	id   string
	root string

	m sync.Mutex

	// initial (immutable) config for the container
	config *configs.Config

	ct *libct.Container

	session *libct.Session

	initProcess *Process

	systemd bool
}

// ID returns the container's unique ID
func (c *libctContainer) ID() string {
	return c.id
}

// Config returns the initial configuration for the container that was used
// during initializtion of the container
func (c *libctContainer) Config() configs.Config {
	return *c.config
}

// Status returns the containers current status
func (c *libctContainer) currentStatus() (Status, error) {
	if c.initProcess == nil {
		return Destroyed, nil
	}
	pid, err := c.initProcess.Pid()
	if err != nil {
		return 0, err
	}
	// return Running if the init process is alive
	if err := syscall.Kill(pid, 0); err != nil {
		if err == syscall.ESRCH {
			c.ct.Wait()
			return Destroyed, nil
		}

		return 0, newSystemError(err)
	}

	state, err := c.ct.State()
	if err != nil {
		return 0, newSystemError(err)
	}
	switch state {
	case libct.CT_RUNNING:
		return Running, nil
	case libct.CT_PAUSED:
		return Paused, nil
	}
	return 0, newSystemError(fmt.Errorf("Unknown state: %d", state))
}

func (c *libctContainer) Status() (Status, error) {
	c.m.Lock()
	defer c.m.Unlock()

	return c.currentStatus()
}

func (c *libctContainer) State() (*State, error) {
	status, err := c.currentStatus()
	if err != nil {
		return nil, err
	}
	if status == Destroyed {
		return nil, newGenericError(fmt.Errorf("container destroyed"), ContainerNotExists)
	}
	pid, err := c.initProcess.Pid()
	if err != nil {
		return nil, newSystemError(err)
	}
	startTime, err := system.GetProcessStartTime(pid)
	if err != nil {
		return nil, err
	}
	state := &State{
		ID:                   c.ID(),
		Config:               *c.config,
		InitProcessPid:       pid,
		InitProcessStartTime: startTime,
		NamespacePaths:       make(map[configs.NamespaceType]string),
	}
	for _, ns := range c.config.Namespaces {
		state.NamespacePaths[ns.Type] = ns.GetPath(pid)
	}
	for _, nsType := range configs.NamespaceTypes() {
		if _, ok := state.NamespacePaths[nsType]; !ok {
			ns := configs.Namespace{Type: nsType}
			state.NamespacePaths[ns.Type] = ns.GetPath(pid)
		}
	}
	return state, nil
}

func (c *libctContainer) updateState() error {
	state, err := c.State()
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(c.root, stateFilename))
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(state)
}

// Destroy kills all running process inside the container and cleans up any
// state left on the filesystem
func (c *libctContainer) Destroy() error {
	c.m.Lock()
	defer c.m.Unlock()

	// FIXME c.ct.Status() != Destroyed
	c.ct.Wait()
	c.ct.Destroy()

	if err := os.RemoveAll(c.root); err == nil {
		return err
	}

	return nil
}

// Processes return the PIDs for processes running inside the container
func (c *libctContainer) Processes() ([]int, error) {
	return c.ct.Processes()
}

// Pause pauses all processes inside the container
func (c *libctContainer) Pause() error {
	return c.ct.Pause()
}

// Resume unpause all processes inside the container
func (c *libctContainer) Resume() error {
	return c.ct.Resume()
}

// getEnabledCapabilities returns the capabilities that should not be dropped by the container.
func getEnabledCapabilities(capList []string) (uint64, error) {
	var keep uint64 = 0
	for _, c := range capList {
		v, ok := capabilityList[c]
		if !ok {
			return 0, newGenericError(fmt.Errorf("unknown capability %q", c), ConfigInvalid)
		}
		keep |= uint64(1) << uint(v)
	}
	return keep, nil
}

func dropBoundingSet(ct *libct.ProcessDesc, capabilities []string) error {
	caps, err := getEnabledCapabilities(capabilities)
	if err != nil {
		return err
	}

	if err := ct.SetCaps(caps, libct.CAPS_BSET); err != nil {
		return newSystemError(err)
	}

	return nil
}

type libctProcessOps struct {
	p *libct.ProcessDesc
}

func (p *libctProcessOps) pid() int {
	pid, err := p.p.GetPid()
	if err != nil {
		log.Warn(err)
		pid = math.MinInt32
	}
	return pid
}

func (p *libctProcessOps) wait() (*os.ProcessState, error) {
	return p.p.Wait()
}

func (p *libctProcessOps) signal(sig os.Signal) error {
	process, err := os.FindProcess(p.pid())
	if err != nil {
		return err
	}

	return process.Signal(sig)
}

func (c *libctContainer) load() error {
	var err error

	if c.systemd {
		if err := c.ct.SetOption(libct.LIBCT_OPT_SYSTEMD); err != nil {
			return newSystemError(err)
		}
	}

	for n, v := range c.config.SystemProperties {
		if err := c.ct.SetSysctl(n, v); err != nil {
			return newSystemError(err)
		}
	}

	if err := c.addUidGidMappings(); err != nil {
		return newSystemError(err)
	}

	err = c.ct.SetNsMask(uint64(c.config.Namespaces.CloneFlags()))
	if err != nil {
		return newSystemError(err)
	}

	if err := c.joinExistingNamespaces(); err != nil {
		return err
	}

	if err := c.setupMountNamespace(); err != nil {
		return err
	}

	if err := c.setupNetwork(); err != nil {
		return fmt.Errorf("setup networking %s", err)
	}

	if err = c.setupCgroups(); err != nil {
		return newSystemError(err)
	}

	return nil
}

func (c *libctContainer) Start(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()

	status, err := c.currentStatus()
	if err != nil {
		return err
	}

	pd, err := c.session.ProcessCreateDesc()
	if err != nil {
		return newSystemError(err)
	}

	for i := range process.ExtraFiles {
		pd.ExtraFiles = append(pd.ExtraFiles, process.ExtraFiles[i])
	}

	if err := pd.SetParentDeathSignal(syscall.SIGKILL); err != nil {
		return newSystemError(err)
	}
	capabilities := process.Capabilities
	if capabilities == nil {
		capabilities = c.config.Capabilities
	}
	if err := dropBoundingSet(pd, capabilities); err != nil {
		return err
	}

	if err := pd.SetEnv(process.Env); err != nil {
		return err
	}

	if err := c.setupRlimits(pd); err != nil {
		return err
	}

	if process.User == "" {
		process.User = fmt.Sprintf("%d", syscall.Getuid())
	}

	if err := pd.SetUser(process.User); err != nil {
		return err
	}

	pd.Stdin = process.Stdin
	pd.Stdout = process.Stdout
	pd.Stderr = process.Stderr

	if status != Destroyed {
		if process.consolePath != "" {

			f, err := os.OpenFile(process.consolePath, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			pd.Stdin = f
			pd.Stdout = f
			pd.Stderr = f
			err = c.ct.SetConsoleFd(f)
			if err != nil {
				return newSystemError(err)
			}
		}
		err = c.ct.EnterExecve(pd, process.Args[0], process.Args, nil)
		if err != nil {
			return newSystemError(err)
		}

		process.ops = &libctProcessOps{p: pd}

		return nil
	}

	if process.consolePath != "" {
		pd.Stdin = libct.Console
		pd.Stdout = libct.Console
		pd.Stderr = libct.Console
		err = c.ct.SetConsoleFd(libct.Console)
		if err != nil {
			return newSystemError(err)
		}
	}

	err = c.ct.SpawnExecve(pd, process.Args[0], process.Args, nil)
	if err != nil {
		return newSystemError(err)
	}

	process.ops = &libctProcessOps{p: pd}

	c.initProcess = process

	c.updateState()

	return nil
}

func (c *libctContainer) setupNetwork() error {
	for _, config := range c.config.Networks {
		strategy, err := libctGetStrategy(config.Type)
		if err != nil {
			return err
		}

		err = strategy.create(c.ct, (*configs.Network)(config))
		if err != nil {
			return err
		}
	}

	return nil
}

var libctFlagsMap map[int]int = map[int]int{
	syscall.MS_NOEXEC:      libct.CT_FS_NOEXEC,
	syscall.MS_NOSUID:      libct.CT_FS_NOSUID,
	syscall.MS_NODEV:       libct.CT_FS_NODEV,
	syscall.MS_STRICTATIME: libct.CT_FS_STRICTATIME,
	syscall.MS_RDONLY:      libct.CT_FS_RDONLY,
	syscall.MS_REC:         libct.CT_FS_REC,
	syscall.MS_BIND:        libct.CT_FS_BIND,
}

func libctFlags(flags int) (int, error) {
	var libctFlags int = 0

	for k, v := range libctFlagsMap {
		if k&flags != 0 {
			libctFlags |= v
			flags &= ^k
		}
	}

	if flags != 0 {
		return 0, newGenericError(fmt.Errorf("Unknown flags: %x", flags), ConfigInvalid)
	}

	return libctFlags, nil
}

func (c *libctContainer) libctMount(m *configs.Mount, mountLabel string) error {
	var flags int

	flags, err := libctFlags(m.Flags)
	if err != nil {
		return err
	}

	switch m.Device {
	case "bind":
		flags |= libct.CT_FS_BIND
		// fallthrough
	default:
		var pre, post []libct.Command
		for _, c := range m.PremountCmds {
			lc := libct.Command{
				Dir:  c.Dir,
				Path: c.Path,
				Args: append([]string{c.Path}, c.Args...),
				Env:  c.Env,
			}
			pre = append(pre, lc)
		}
		for _, c := range m.PostmountCmds {
			lc := libct.Command{
				Dir:  c.Dir,
				Path: c.Path,
				Args: append([]string{c.Path}, c.Args...),
				Env:  c.Env,
			}
			post = append(post, lc)
		}
		if err := c.ct.AddMount(m.Source, m.Destination, flags, m.Device, m.Data, pre, post); err != nil {
			return newSystemError(err)
		}
	}

	return nil
}

func (c *libctContainer) setupMountNamespace() error {
	rootfs, err := utils.ResolveRootfs(c.config.Rootfs)
	if err != nil {
		return err
	}

	if err := c.ct.SetRoot(rootfs); err != nil {
		return newSystemError(err)
	}

	for _, m := range c.config.Mounts {
		if err := c.libctMount(m, c.config.MountLabel); err != nil {
			return newSystemError(err)
		}
	}

	return nil
}

func (c *libctContainer) NotifyOOM() (<-chan struct{}, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (c *libctContainer) Set(config configs.Config) error {
	return fmt.Errorf("not implemented yet")
}

func (c *libctContainer) setupRlimits(pd *libct.ProcessDesc) error {
	for _, rlimit := range c.config.Rlimits {
		if err := pd.SetRlimit(rlimit.Type, rlimit.Soft, rlimit.Hard); err != nil {
			return newSystemError(err)
		}
	}

	return nil
}

// joinExistingNamespaces gets all the namespace paths specified for the container and
// does a setns on the namespace fd so that the current process joins the namespace.
func (c *libctContainer) joinExistingNamespaces() error {
	for _, ns := range c.config.Namespaces {
		if ns.Path == "" {
			continue
		}

		if err := c.ct.SetNsPath(ns.Syscall(), ns.Path); err != nil {
			return err
		}
	}
	return nil
}

func (c *libctContainer) addUidGidMappings() error {
	if c.config.UidMappings != nil {
		for _, um := range c.config.UidMappings {
			c.ct.AddUidMap(um.ContainerID, um.HostID, um.Size)
		}
	}
	if c.config.GidMappings != nil {
		for _, gm := range c.config.GidMappings {
			c.ct.AddGidMap(gm.ContainerID, gm.HostID, gm.Size)
		}
	}
	return nil
}
