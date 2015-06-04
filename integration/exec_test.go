package integration

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/cgroups/systemd"
	"github.com/docker/libcontainer/configs"
)

func TestExecPS(t *testing.T) {
	testExecPS(t, false)
}

func TestUsernsExecPS(t *testing.T) {
	if _, err := os.Stat("/proc/self/ns/user"); os.IsNotExist(err) {
		t.Skip("userns is unsupported")
	}
	testExecPS(t, true)
}

func testExecPS(t *testing.T, userns bool) {
	if testing.Short() {
		return
	}
	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)
	config := newTemplateConfig(rootfs)
	if userns {
		config.UidMappings = []configs.IDMap{{0, 0, 1000}}
		config.GidMappings = []configs.IDMap{{0, 0, 1000}}
		config.Namespaces = append(config.Namespaces, configs.Namespace{Type: configs.NEWUSER})
	}

	buffers, exitCode, err := runContainer(config, "", "ps")
	if err != nil {
		t.Fatalf("%s: %s", buffers, err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code not 0. code %d stderr %q", exitCode, buffers.Stderr)
	}
	lines := strings.Split(buffers.Stdout.String(), "\n")
	if len(lines) < 2 {
		t.Fatalf("more than one process running for output %q", buffers.Stdout.String())
	}
	expected := `1 root     ps`
	actual := strings.Trim(lines[1], "\n ")
	if actual != expected {
		t.Fatalf("expected output %q but received %q", expected, actual)
	}
}

func TestIPCPrivate(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	l, err := os.Readlink("/proc/1/ns/ipc")
	ok(t, err)

	config := newTemplateConfig(rootfs)
	buffers, exitCode, err := runContainer(config, "", "readlink", "/proc/self/ns/ipc")
	ok(t, err)

	if exitCode != 0 {
		t.Fatalf("exit code not 0. code %d stderr %q", exitCode, buffers.Stderr)
	}

	if actual := strings.Trim(buffers.Stdout.String(), "\n"); actual == l {
		t.Fatalf("ipc link should be private to the container but equals host %q %q", actual, l)
	}
}

func TestIPCHost(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	l, err := os.Readlink("/proc/1/ns/ipc")
	ok(t, err)

	config := newTemplateConfig(rootfs)
	config.Namespaces.Remove(configs.NEWIPC)
	buffers, exitCode, err := runContainer(config, "", "readlink", "/proc/self/ns/ipc")
	ok(t, err)

	if exitCode != 0 {
		t.Fatalf("exit code not 0. code %d stderr %q", exitCode, buffers.Stderr)
	}

	if actual := strings.Trim(buffers.Stdout.String(), "\n"); actual != l {
		t.Fatalf("ipc link not equal to host link %q %q", actual, l)
	}
}

func TestIPCJoinPath(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	l, err := os.Readlink("/proc/1/ns/ipc")
	ok(t, err)

	config := newTemplateConfig(rootfs)
	config.Namespaces.Add(configs.NEWIPC, "/proc/1/ns/ipc")

	buffers, exitCode, err := runContainer(config, "", "readlink", "/proc/self/ns/ipc")
	ok(t, err)

	if exitCode != 0 {
		t.Fatalf("exit code not 0. code %d stderr %q", exitCode, buffers.Stderr)
	}

	if actual := strings.Trim(buffers.Stdout.String(), "\n"); actual != l {
		t.Fatalf("ipc link not equal to host link %q %q", actual, l)
	}
}

func TestIPCBadPath(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	config.Namespaces.Add(configs.NEWIPC, "/proc/1/ns/ipcc")

	_, _, err = runContainer(config, "", "true")
	if err == nil {
		t.Fatal("container succeeded with bad ipc path")
	}
}

func TestRlimit(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	out, _, err := runContainer(config, "", "/bin/sh", "-c", "ulimit -n")
	ok(t, err)
	if limit := strings.TrimSpace(out.Stdout.String()); limit != "1025" {
		t.Fatalf("expected rlimit to be 1025, got %s", limit)
	}
}

func newTestRoot() (string, error) {
	dir, err := ioutil.TempDir("", "libcontainer")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func TestEnter(t *testing.T) {
	if testing.Short() {
		return
	}
	root, err := newTestRoot()
	ok(t, err)
	defer os.RemoveAll(root)

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)

	container, err := factory.Create("test", config)
	ok(t, err)
	defer container.Destroy()

	// Execute a first process in the container
	stdinR, stdinW, err := os.Pipe()
	ok(t, err)

	var stdout, stdout2 bytes.Buffer

	pconfig := libcontainer.Process{
		Args:   []string{"sh", "-c", "cat && readlink /proc/self/ns/pid"},
		Env:    standardEnvironment,
		Stdin:  stdinR,
		Stdout: &stdout,
	}
	err = container.Start(&pconfig)
	stdinR.Close()
	defer stdinW.Close()
	ok(t, err)
	pid, err := pconfig.Pid()
	ok(t, err)

	// Execute another process in the container
	stdinR2, stdinW2, err := os.Pipe()
	ok(t, err)
	pconfig2 := libcontainer.Process{
		Env: standardEnvironment,
	}
	pconfig2.Args = []string{"sh", "-c", "cat && readlink /proc/self/ns/pid"}
	pconfig2.Stdin = stdinR2
	pconfig2.Stdout = &stdout2

	err = container.Start(&pconfig2)
	stdinR2.Close()
	defer stdinW2.Close()
	ok(t, err)

	pid2, err := pconfig2.Pid()
	ok(t, err)

	processes, err := container.Processes()
	ok(t, err)

	n := 0
	for i := range processes {
		if processes[i] == pid || processes[i] == pid2 {
			n++
		}
	}
	if n != 2 {
		t.Fatal("unexpected number of processes", processes, pid, pid2)
	}

	// Wait processes
	stdinW2.Close()
	waitProcess(&pconfig2, t)

	stdinW.Close()
	waitProcess(&pconfig, t)

	// Check that both processes live in the same pidns
	pidns := string(stdout.Bytes())
	ok(t, err)

	pidns2 := string(stdout2.Bytes())
	ok(t, err)

	if pidns != pidns2 {
		t.Fatal("The second process isn't in the required pid namespace", pidns, pidns2)
	}
}

func TestProcessEnv(t *testing.T) {
	if testing.Short() {
		return
	}
	root, err := newTestRoot()
	ok(t, err)
	defer os.RemoveAll(root)

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)

	container, err := factory.Create("test", config)
	ok(t, err)
	defer container.Destroy()

	var stdout bytes.Buffer
	pconfig := libcontainer.Process{
		Args: []string{"sh", "-c", "env"},
		Env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOSTNAME=integration",
			"TERM=xterm",
			"FOO=BAR",
		},
		Stdin:  nil,
		Stdout: &stdout,
	}
	err = container.Start(&pconfig)
	ok(t, err)

	// Wait for process
	waitProcess(&pconfig, t)

	outputEnv := string(stdout.Bytes())

	// Check that the environment has the key/value pair we added
	if !strings.Contains(outputEnv, "FOO=BAR") {
		t.Fatal("Environment doesn't have the expected FOO=BAR key/value pair: ", outputEnv)
	}

	// Make sure that HOME is set
	if !strings.Contains(outputEnv, "HOME=/root") {
		t.Fatal("Environment doesn't have HOME set: ", outputEnv)
	}
}

func TestProcessCaps(t *testing.T) {
	if testing.Short() {
		return
	}
	root, err := newTestRoot()
	ok(t, err)
	defer os.RemoveAll(root)

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)

	container, err := factory.Create("test", config)
	ok(t, err)
	defer container.Destroy()

	processCaps := append(config.Capabilities, "NET_ADMIN")

	var stdout bytes.Buffer
	pconfig := libcontainer.Process{
		Args:         []string{"sh", "-c", "cat /proc/self/status"},
		Env:          standardEnvironment,
		Capabilities: processCaps,
		Stdin:        nil,
		Stdout:       &stdout,
	}
	err = container.Start(&pconfig)
	ok(t, err)

	// Wait for process
	waitProcess(&pconfig, t)

	outputStatus := string(stdout.Bytes())

	lines := strings.Split(outputStatus, "\n")

	effectiveCapsLine := ""
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if strings.Contains(line, "CapEff:") {
			effectiveCapsLine = line
			break
		}
	}

	if effectiveCapsLine == "" {
		t.Fatal("Couldn't find effective caps: ", outputStatus)
	}

	parts := strings.Split(effectiveCapsLine, ":")
	effectiveCapsStr := strings.TrimSpace(parts[1])

	effectiveCaps, err := strconv.ParseUint(effectiveCapsStr, 16, 64)
	if err != nil {
		t.Fatal("Could not parse effective caps", err)
	}

	var netAdminMask uint64
	var netAdminBit uint
	netAdminBit = 12 // from capability.h
	netAdminMask = 1 << netAdminBit
	if effectiveCaps&netAdminMask != netAdminMask {
		t.Fatal("CAP_NET_ADMIN is not set as expected")
	}
}

func TestFreeze(t *testing.T) {
	testFreeze(t, false)
}

func TestSystemdFreeze(t *testing.T) {
	if !systemd.UseSystemd() {
		t.Skip("Systemd is unsupported")
	}
	testFreeze(t, true)
}

func testFreeze(t *testing.T, systemd bool) {
	if testing.Short() {
		return
	}
	root, err := newTestRoot()
	ok(t, err)
	defer os.RemoveAll(root)

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	f := factory
	if systemd {
		f = systemdFactory
	}

	container, err := f.Create("test", config)
	ok(t, err)
	defer container.Destroy()

	stdinR, stdinW, err := os.Pipe()
	ok(t, err)

	pconfig := &libcontainer.Process{
		Args:  []string{"cat"},
		Env:   standardEnvironment,
		Stdin: stdinR,
	}
	err = container.Start(pconfig)
	stdinR.Close()
	defer stdinW.Close()
	ok(t, err)

	err = container.Pause()
	ok(t, err)
	state, err := container.Status()
	ok(t, err)
	err = container.Resume()
	ok(t, err)
	if state != libcontainer.Paused {
		t.Fatal("Unexpected state: ", state)
	}

	stdinW.Close()
	waitProcess(pconfig, t)
}

func TestCpuShares(t *testing.T) {
	testCpuShares(t, false)
}

func TestSystemdCpuShares(t *testing.T) {
	if !systemd.UseSystemd() {
		t.Skip("Systemd is unsupported")
	}
	testCpuShares(t, true)
}

func testCpuShares(t *testing.T, systemd bool) {
	if testing.Short() {
		return
	}
	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	if systemd {
		config.Cgroups.Slice = "system.slice"
	}
	config.Cgroups.CpuShares = 1

	_, _, err = runContainer(config, "", "ps")
	if err == nil {
		t.Fatalf("runContainer should failed with invalid CpuShares")
	}
}

func TestContainerState(t *testing.T) {
	if testing.Short() {
		return
	}
	root, err := newTestRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	rootfs, err := newRootfs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	l, err := os.Readlink("/proc/1/ns/ipc")
	if err != nil {
		t.Fatal(err)
	}

	config := newTemplateConfig(rootfs)
	config.Namespaces = configs.Namespaces([]configs.Namespace{
		{Type: configs.NEWNS},
		{Type: configs.NEWUTS},
		// host for IPC
		//{Type: configs.NEWIPC},
		{Type: configs.NEWPID},
		{Type: configs.NEWNET},
	})

	container, err := factory.Create("test", config)
	if err != nil {
		t.Fatal(err)
	}
	defer container.Destroy()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &libcontainer.Process{
		Args:  []string{"cat"},
		Env:   standardEnvironment,
		Stdin: stdinR,
	}
	err = container.Start(p)
	if err != nil {
		t.Fatal(err)
	}
	stdinR.Close()
	defer stdinW.Close()

	st, err := container.State()
	if err != nil {
		t.Fatal(err)
	}

	l1, err := os.Readlink(st.NamespacePaths[configs.NEWIPC])
	if err != nil {
		t.Fatal(err)
	}
	if l1 != l {
		t.Fatal("Container using non-host ipc namespace")
	}
	stdinW.Close()
	waitProcess(p, t)
}

func TestPassExtraFiles(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootfs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)

	container, err := factory.Create("test", config)
	if err != nil {
		t.Fatal(err)
	}
	defer container.Destroy()

	var stdout bytes.Buffer
	pipeout1, pipein1, err := os.Pipe()
	pipeout2, pipein2, err := os.Pipe()
	process := libcontainer.Process{
		Args:       []string{"sh", "-c", "cd /proc/$$/fd; echo -n *; echo -n 1 >3; echo -n 2 >4"},
		Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		ExtraFiles: []*os.File{pipein1, pipein2},
		Stdin:      nil,
		Stdout:     &stdout,
	}
	err = container.Start(&process)
	if err != nil {
		t.Fatal(err)
	}

	waitProcess(&process, t)

	out := string(stdout.Bytes())
	// fd 5 is the directory handle for /proc/$$/fd
	if out != "0 1 2 3 4 5" {
		t.Fatalf("expected to have the file descriptors '0 1 2 3 4 5' passed to init, got '%s'", out)
	}
	var buf = []byte{0}
	_, err = pipeout1.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	out1 := string(buf)
	if out1 != "1" {
		t.Fatalf("expected first pipe to receive '1', got '%s'", out1)
	}

	_, err = pipeout2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	out2 := string(buf)
	if out2 != "2" {
		t.Fatalf("expected second pipe to receive '2', got '%s'", out2)
	}
}

func TestMountCmds(t *testing.T) {
	if testing.Short() {
		return
	}
	root, err := newTestRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	rootfs, err := newRootfs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	tmpDir, err := ioutil.TempDir("", "tmpdir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := newTemplateConfig(rootfs)
	config.Mounts = append(config.Mounts, &configs.Mount{
		Source:      tmpDir,
		Destination: "/tmp",
		Device:      "bind",
		Flags:       syscall.MS_BIND | syscall.MS_REC,
		PremountCmds: []configs.Command{
			{Path: "touch", Args: []string{filepath.Join(tmpDir, "hello")}},
			{Path: "touch", Args: []string{filepath.Join(tmpDir, "world")}},
		},
		PostmountCmds: []configs.Command{
			{Path: "cp", Args: []string{filepath.Join(rootfs, "tmp", "hello"), filepath.Join(rootfs, "tmp", "hello-backup")}},
			{Path: "cp", Args: []string{filepath.Join(rootfs, "tmp", "world"), filepath.Join(rootfs, "tmp", "world-backup")}},
		},
	})

	container, err := factory.Create("test", config)
	if err != nil {
		t.Fatal(err)
	}
	defer container.Destroy()

	pconfig := libcontainer.Process{
		Args: []string{"sh", "-c", "env"},
		Env:  standardEnvironment,
	}
	err = container.Start(&pconfig)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for process
	waitProcess(&pconfig, t)

	entries, err := ioutil.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"hello", "hello-backup", "world", "world-backup"}
	for i, e := range entries {
		if e.Name() != expected[i] {
			t.Errorf("Got(%s), expect %s", e.Name(), expected[i])
		}
	}
}

func TestSystemProperties(t *testing.T) {
	if testing.Short() {
		return
	}
	root, err := newTestRoot()
	ok(t, err)
	defer os.RemoveAll(root)

	rootfs, err := newRootfs()
	ok(t, err)
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	config.SystemProperties = map[string]string{
		"kernel.shmmni": "8192",
	}

	container, err := factory.Create("test", config)
	ok(t, err)
	defer container.Destroy()

	var stdout bytes.Buffer
	pconfig := libcontainer.Process{
		Args:   []string{"sh", "-c", "cat /proc/sys/kernel/shmmni"},
		Env:    standardEnvironment,
		Stdin:  nil,
		Stdout: &stdout,
	}
	err = container.Start(&pconfig)
	ok(t, err)

	// Wait for process
	waitProcess(&pconfig, t)

	shmmniOutput := strings.TrimSpace(string(stdout.Bytes()))
	if shmmniOutput != "8192" {
		t.Fatalf("kernel.shmmni property expected to be 8192, but is %s", shmmniOutput)
	}
}

func genSeccompConfigFile(file string, calls []int) error {
	callBegin := 0
	callEnd := 0
	if runtime.GOARCH == "386" {
		callEnd = 340
	} else if runtime.GOARCH == "amd64" {
		callEnd = 302
	} else if runtime.GOARCH == "arm" {
		callEnd = 377
	} else if runtime.GOARCH == "arm64" {
		callEnd = 281
	} else if runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" {
		callEnd = 354
	}

	conf := fmt.Sprintf("%d\nwhitelist\n", 1)
	i := 0
	nr := callBegin
	for nr <= callEnd {
		j := 0
		for _, key := range calls {
			if nr == key {
				break
			}
			j++
		}
		if j == len(calls) {
			callfilter := fmt.Sprintf("%d\n", nr)
			conf += callfilter
			i++
		}
		nr++
	}
	fout, err := os.Create(file)
	defer fout.Close()
	if err == nil {
		fout.WriteString(conf)
	}
	return nil
}

func genSeccompSyscall(configFile string, Seccomps *configs.SeccompConf) error {
	f, err := os.Open(configFile)
	defer f.Close()
	if nil == err {
		buff := bufio.NewReader(f)
		firstl, err := buff.ReadString('\n')
		if err != nil || io.EOF == err {
			return errors.New("initSeccomp ReadString, firstl")
		}
		ver := 0
		fmt.Sscanf(firstl, "%d\n", &ver)
		if err != nil || 1 != ver {
			return errors.New("initSeccomp Sscanf")
		}

		secondl, err := buff.ReadString('\n')
		if err != nil || io.EOF == err || strings.EqualFold(secondl, "whitelist") {
			return errors.New("initSeccomp ReadString, secondl")
		}
		nr := 0
		for {
			line, err := buff.ReadString('\n')
			if err != nil || io.EOF == err {
				break
			}
			fmt.Sscanf(line, "%d\n", &nr)
			Seccomps.SysCalls = append(Seccomps.SysCalls, nr)
		}
		return nil
	}
	return nil
}

func TestSeccompNotStat(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootfs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)
	config := newTemplateConfig(rootfs)
	exceptCall := []int{syscall.SYS_STAT}
	genSeccompConfigFile("seccomp.conf", exceptCall)
	genSeccompSyscall("seccomp.conf", &config.Seccomps)
	out, _, err := runContainer(config, "", "/bin/sh", "-c", "ls / -l")
	if err == nil {
		t.Fatal("runontainer[ls without SYS_STAT] should be failed")
	} else {
		fmt.Println(out)
	}
}

func TestSeccompStat(t *testing.T) {
	if testing.Short() {
		return
	}
	rootfs, err := newRootfs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	exceptCall := []int{}
	genSeccompConfigFile("seccomp.conf", exceptCall)
	genSeccompSyscall("seccomp.conf", &config.Seccomps)
	out, _, err := runContainer(config, "", "/bin/sh", "-c", "ls / -l")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(out)
}
