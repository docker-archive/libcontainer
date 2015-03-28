// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/configs"
)

type linuxContainer struct {
	id            string
	root          string
	config        *configs.Config
	cgroupManager cgroups.Manager
	initPath      string
	initArgs      []string
	initProcess   parentProcess
	criuPath      string		// criu v1.4 or newer
	m             sync.Mutex
}

// ID returns the container's unique ID
func (c *linuxContainer) ID() string {
	return c.id
}

// Config returns the container's configuration
func (c *linuxContainer) Config() configs.Config {
	return *c.config
}

func (c *linuxContainer) Status() (Status, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentStatus()
}

func (c *linuxContainer) State() (*State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentState()
}

func (c *linuxContainer) Processes() ([]int, error) {
	pids, err := c.cgroupManager.GetPids()
	if err != nil {
		return nil, newSystemError(err)
	}
	return pids, nil
}

func (c *linuxContainer) Stats() (*Stats, error) {
	var (
		err   error
		stats = &Stats{}
	)
	if stats.CgroupStats, err = c.cgroupManager.GetStats(); err != nil {
		return stats, newSystemError(err)
	}
	for _, iface := range c.config.Networks {
		switch iface.Type {
		case "veth":
			istats, err := getNetworkInterfaceStats(iface.HostInterfaceName)
			if err != nil {
				return stats, newSystemError(err)
			}
			stats.Interfaces = append(stats.Interfaces, istats)
		}
	}
	return stats, nil
}

func (c *linuxContainer) Set(config configs.Config) error {
	c.m.Lock()
	defer c.m.Unlock()
	c.config = &config
	return c.cgroupManager.Set(c.config)
}

func (c *linuxContainer) Start(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	doInit := status == Destroyed
	parent, err := c.newParentProcess(process, doInit)
	if err != nil {
		return newSystemError(err)
	}
	if err := parent.start(); err != nil {
		// terminate the process to ensure that it properly is reaped.
		if err := parent.terminate(); err != nil {
			log.Warn(err)
		}
		return newSystemError(err)
	}
	process.ops = parent
	if doInit {
		c.updateState(parent)
	}
	return nil
}

func (c *linuxContainer) newParentProcess(p *Process, doInit bool) (parentProcess, error) {
	parentPipe, childPipe, err := newPipe()
	if err != nil {
		return nil, newSystemError(err)
	}
	cmd, err := c.commandTemplate(p, childPipe)
	if err != nil {
		return nil, newSystemError(err)
	}
	if !doInit {
		return c.newSetnsProcess(p, cmd, parentPipe, childPipe), nil
	}
	return c.newInitProcess(p, cmd, parentPipe, childPipe)
}

func (c *linuxContainer) commandTemplate(p *Process, childPipe *os.File) (*exec.Cmd, error) {
	cmd := &exec.Cmd{
		Path: c.initPath,
		Args: c.initArgs,
	}
	cmd.Stdin = p.Stdin
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	cmd.Dir = c.config.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.ExtraFiles = []*os.File{childPipe}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	if c.config.ParentDeathSignal > 0 {
		cmd.SysProcAttr.Pdeathsig = syscall.Signal(c.config.ParentDeathSignal)
	}
	return cmd, nil
}

func (c *linuxContainer) newInitProcess(p *Process, cmd *exec.Cmd, parentPipe, childPipe *os.File) (*initProcess, error) {
	t := "_LIBCONTAINER_INITTYPE=standard"
	cloneFlags := c.config.Namespaces.CloneFlags()
	if cloneFlags&syscall.CLONE_NEWUSER != 0 {
		if err := c.addUidGidMappings(cmd.SysProcAttr); err != nil {
			// user mappings are not supported
			return nil, err
		}
		// Default to root user when user namespaces are enabled.
		if cmd.SysProcAttr.Credential == nil {
			cmd.SysProcAttr.Credential = &syscall.Credential{}
		}
	}
	cmd.Env = append(cmd.Env, t)
	cmd.SysProcAttr.Cloneflags = cloneFlags
	return &initProcess{
		cmd:        cmd,
		childPipe:  childPipe,
		parentPipe: parentPipe,
		manager:    c.cgroupManager,
		config:     c.newInitConfig(p),
	}, nil
}

func (c *linuxContainer) newSetnsProcess(p *Process, cmd *exec.Cmd, parentPipe, childPipe *os.File) *setnsProcess {
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("_LIBCONTAINER_INITPID=%d", c.initProcess.pid()),
		"_LIBCONTAINER_INITTYPE=setns",
	)

	if p.consolePath != "" {
		cmd.Env = append(cmd.Env, "_LIBCONTAINER_CONSOLE_PATH="+p.consolePath)
	}

	// TODO: set on container for process management
	return &setnsProcess{
		cmd:         cmd,
		cgroupPaths: c.cgroupManager.GetPaths(),
		childPipe:   childPipe,
		parentPipe:  parentPipe,
		config:      c.newInitConfig(p),
	}
}

func (c *linuxContainer) newInitConfig(process *Process) *initConfig {
	return &initConfig{
		Config:  c.config,
		Args:    process.Args,
		Env:     process.Env,
		User:    process.User,
		Cwd:     process.Cwd,
		Console: process.consolePath,
	}
}

func newPipe() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

func (c *linuxContainer) Destroy() error {
	c.m.Lock()
	defer c.m.Unlock()
	// Since the state.json and CRIU image files are in the c.root
	// directory, we should not remove it after checkpoint.  Also,
	// when     CRIU exits after restore, we should not kill the processes.
	if _, err := os.Stat(filepath.Join(c.root, "checkpoint")); err == nil {
		return nil
	}
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status != Destroyed {
		return newGenericError(fmt.Errorf("container is not destroyed"), ContainerNotStopped)
	}
	if !c.config.Namespaces.Contains(configs.NEWPID) {
		if err := killCgroupProcesses(c.cgroupManager); err != nil {
			log.Warn(err)
		}
	}
	err = c.cgroupManager.Destroy()
	if rerr := os.RemoveAll(c.root); err == nil {
		err = rerr
	}
	c.initProcess = nil
	return err
}

func (c *linuxContainer) Pause() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.cgroupManager.Freeze(configs.Frozen)
}

func (c *linuxContainer) Resume() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.cgroupManager.Freeze(configs.Thawed)
}

func (c *linuxContainer) NotifyOOM() (<-chan struct{}, error) {
	return notifyOnOOM(c.cgroupManager.GetPaths())
}

func (c *linuxContainer) Checkpoint() error {
	c.m.Lock()
	defer c.m.Unlock()
	// XXX The pathname to CRIU's image directory should
	//     be passed in and ideally point to somewhere
	//     outside the container's root.
	dir := filepath.Join(c.root, "checkpoint")
	// Since a container can be C/R'ed multiple times,
	// the checkpoint directory may already exist.
	if err := os.Mkdir(dir, 0655); err != nil && !os.IsExist(err) {
		return err
	}
	args := []string{
		"dump", "-v4",
		"-D", dir,
		"-o", "dump.log",
		"--root", c.config.Rootfs,
		"--manage-cgroups", "--evasive-devices",
		"-t", strconv.Itoa(c.initProcess.pid()),
	}
	for _, m := range c.config.Mounts {
		if m.Device == "bind" {
			args = append(args,
				"--ext-mount-map", fmt.Sprintf("%s:%s", m.Destination, m.Destination))
		}
	}
	if err := exec.Command(c.criuPath, args...).Run(); err != nil {
		return err
	}
	return nil
}

func (c *linuxContainer) Restore(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()

	pidfile := filepath.Join(c.root, "restoredpid")
	// Make sure pidfile doesn't already exist from a
	// previous restore.  Otherwise, CRIU will fail.
	if err := os.Remove(pidfile); err != nil && !os.IsNotExist(err) {
		return err
	}

	act_r, act_w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer act_r.Close()
	defer act_w.Close()

	// StdFds have to be initialized while CRIU is working. An action-script
	// is used to stop CRIU. This is a dirty hack.
	// In a future we are going to use "criu swrk" for this, it will be
	// avaliable in CRIU 1.6
	actionscript := filepath.Join(c.root, "checkpoint", "action-script")
	f, err := os.OpenFile(actionscript, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer os.Remove(actionscript)
	fmt.Fprintf(f, "#!/bin/sh\n")
	fmt.Fprintf(f, "[ \"setup-namespaces\" != \"$CRTOOLS_SCRIPT_ACTION\" ] && exit 0\n")
	fmt.Fprintf(f, "sleep 1000 & pid=$!\n")
	fmt.Fprintf(f, "echo $pid > /proc/%d/fd/%d\n", os.Getpid(), act_w.Fd())
	fmt.Fprintf(f, "wait $pid && exit 1\n")
	fmt.Fprintf(f, "exit 0\n")
	f.Close()

	args := []string{
		"restore", "-v4",
		"-D", filepath.Join(c.root, "checkpoint"),
		"-o", "restore.log",
		"--restore-detached",
		"--restore-sibling",
		"--root", c.config.Rootfs,
		"--pidfile", pidfile,
		"--manage-cgroups", "--evasive-devices",
		"--action-script", actionscript,
	}
	for _, m := range c.config.Mounts {
		if m.Device == "bind" {
			args = append(args, "--ext-mount-map",
				fmt.Sprintf("%s:%s", m.Destination, m.Source))
		}
	}
	// Pipes that were previously set up for std{in,out,err}
	// were removed after checkpoint.  Use the new ones.
	for i := 0; i < 3; i++ {
		if s := c.config.StdFds[i]; strings.Contains(s, "pipe:") {
			args = append(args, "--inherit-fd", fmt.Sprintf("fd[%d]:%s", i, s))
		}
	}

	cmd := exec.Command(c.criuPath, args...)
	cmd.Stdin = process.Stdin
	cmd.Stdout = process.Stdout
	cmd.Stderr = process.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	sync := make(chan error)
	go func() {
		var err error
		defer func() {
			if err != nil {
				log.Warn(err)
			}
			sync <- err
			close(sync)
		}()
		pid := math.MinInt32
		_, err = fmt.Fscanf(act_r, "%d", &pid)
		if err != nil {
			return
		}
		p, err := os.FindProcess(pid)
		if err != nil {
			return
		}

		err = saveStdPipes(cmd.Process.Pid, c.config)
		if err != nil {
			return
		}
		p.Kill()
	}()

	// cmd.Wait() waits cmd.goroutines which are used for proxying file descriptors.
	// Here we want to wait only the CRIU process.
	st, err := cmd.Process.Wait()
	if err != nil {
		return err
	}
	err = <-sync
	if err != nil {
		log.Warn(err)
	}
	if !st.Success() {
		return fmt.Errorf("criu failed: %s", st.String())
	}
	r, err := newRestoredProcess(pidfile)
	if err != nil {
		return err
	}

	// TODO: crosbymichael restore previous process information by saving the init process information in
	// the conatiner's state file or separate process state files.
	if err := c.updateState(r); err != nil {
		return err
	}
	process.ops = r
	return nil
}

func (c *linuxContainer) updateState(process parentProcess) error {
	c.initProcess = process
	state, err := c.currentState()
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

func (c *linuxContainer) currentStatus() (Status, error) {
	if c.initProcess == nil {
		return Destroyed, nil
	}
	// return Running if the init process is alive
	if err := syscall.Kill(c.initProcess.pid(), 0); err != nil {
		if err == syscall.ESRCH {
			return Destroyed, nil
		}
		return 0, newSystemError(err)
	}
	if c.config.Cgroups != nil && c.config.Cgroups.Freezer == configs.Frozen {
		return Paused, nil
	}
	return Running, nil
}

func (c *linuxContainer) currentState() (*State, error) {
	status, err := c.currentStatus()
	if err != nil {
		return nil, err
	}
	if status == Destroyed {
		return nil, newGenericError(fmt.Errorf("container destroyed"), ContainerNotExists)
	}
	startTime, err := c.initProcess.startTime()
	if err != nil {
		return nil, newSystemError(err)
	}
	state := &State{
		ID:                   c.ID(),
		Config:               *c.config,
		InitProcessPid:       c.initProcess.pid(),
		InitProcessStartTime: startTime,
		CgroupPaths:          c.cgroupManager.GetPaths(),
		NamespacePaths:       make(map[configs.NamespaceType]string),
	}
	for _, ns := range c.config.Namespaces {
		state.NamespacePaths[ns.Type] = ns.GetPath(c.initProcess.pid())
	}
	return state, nil
}
