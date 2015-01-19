package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/namespaces"
)

func TestExecIn(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootFs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	if err := writeConfig(config); err != nil {
		t.Fatalf("failed to write config %s", err)
	}

	containerCmd, statePath, containerErr := startLongRunningContainer(config)
	defer func() {
		// kill the container
		if containerCmd.Process != nil {
			containerCmd.Process.Kill()
		}
		if err := <-containerErr; err != nil {
			t.Fatal(err)
		}
	}()

	// start the exec process
	state, err := libcontainer.GetState(statePath)
	if err != nil {
		t.Fatalf("failed to get state %s", err)
	}
	buffers := newStdBuffers()
	execErr := make(chan error, 1)
	execConfig := &libcontainer.ExecConfig{
		Container: config,
		State:     state,
	}
	var execWait sync.WaitGroup
	execWait.Add(1)
	go func() {
		_, err := namespaces.ExecIn(execConfig, []string{"ps"},
			os.Args[0], "exec", buffers.Stdin, buffers.Stdout, buffers.Stderr,
			"", func(cmd *exec.Cmd) {
				pid := cmd.Process.Pid
				assertCgroups(t, state.CgroupPaths, pid)
				execWait.Done()
			})
		execWait.Wait()
		execErr <- err
	}()
	if err := <-execErr; err != nil {
		t.Fatalf("exec finished with error %s", err)
	}

	out := buffers.Stdout.String()
	if !strings.Contains(out, "sleep 10") || !strings.Contains(out, "ps") {
		t.Fatalf("unexpected running process, output %q", out)
	}
}
		}
		execWait.Done()
	}
	execWait.Add(1)
	go func() {
		_, err := namespaces.ExecIn(execConfig, []string{"ps"},
			os.Args[0], "exec", buffers.Stdin, buffers.Stdout, buffers.Stderr,
			"", startCallback)
		execWait.Wait()
		execErr <- err
	}()
	if err := <-execErr; err != nil {
		t.Fatalf("exec finished with error %s", err)
	}

	out := buffers.Stdout.String()
	if !strings.Contains(out, "sleep 10") || !strings.Contains(out, "ps") {
		t.Fatalf("unexpected running process, output %q", out)
	}
}

func TestExecInRlimit(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootFs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	if err := writeConfig(config); err != nil {
		t.Fatalf("failed to write config %s", err)
	}

	containerCmd, statePath, containerErr := startLongRunningContainer(config)
	defer func() {
		// kill the container
		if containerCmd.Process != nil {
			containerCmd.Process.Kill()
		}
		if err := <-containerErr; err != nil {
			t.Fatal(err)
		}
	}()

	// start the exec process
	state, err := libcontainer.GetState(statePath)
	if err != nil {
		t.Fatalf("failed to get state %s", err)
	}
	buffers := newStdBuffers()
	execErr := make(chan error, 1)
	execConfig := &libcontainer.ExecConfig{
		Container: config,
		State:     state,
	}
	go func() {
		_, err := namespaces.ExecIn(execConfig, []string{"/bin/sh", "-c", "ulimit -n"},
			os.Args[0], "exec", buffers.Stdin, buffers.Stdout, buffers.Stderr,
			"", nil)
		execErr <- err
	}()
	if err := <-execErr; err != nil {
		t.Fatalf("exec finished with error %s", err)
	}

	out := buffers.Stdout.String()
	if limit := strings.TrimSpace(out); limit != "1024" {
		t.Fatalf("expected rlimit to be 1024, got %s", limit)
	}
}

// start a long-running container so we have time to inspect execin processes
func startLongRunningContainer(config *libcontainer.Config) (*exec.Cmd, string, chan error) {
	containerErr := make(chan error, 1)
	containerCmd := &exec.Cmd{}
	var statePath string

	createCmd := func(container *libcontainer.Config, console, dataPath, init string,
		pipe *os.File, args []string) *exec.Cmd {
		containerCmd = namespaces.DefaultCreateCommand(container, console, dataPath, init, pipe, args)
		statePath = dataPath
		return containerCmd
	}

	var containerStart sync.WaitGroup
	containerStart.Add(1)
	go func() {
		buffers := newStdBuffers()
		_, err := namespaces.Exec(config,
			buffers.Stdin, buffers.Stdout, buffers.Stderr,
			"", config.RootFs, []string{"sleep", "10"},
			createCmd, containerStart.Done)
		containerErr <- err
	}()
	containerStart.Wait()

	return containerCmd, statePath, containerErr
}

// asserts that process pid joined the cgroups paths. Non-existing cgroup paths
// are ignored
func assertCgroups(t *testing.T, paths map[string]string, pid int) {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		pids, err := cgroups.ReadProcsFile(p)
		if err != nil {
			t.Errorf("failed to read procs in %q", p)
			continue
		}
		var found bool
		for _, procPID := range pids {
			if procPID == pid {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cgroups %q does not contain exec pid %d", p, pid)
		}
	}
}
