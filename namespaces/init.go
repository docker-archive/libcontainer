// +build linux

package namespaces

/*
#include <linux/securebits.h>
*/
import "C"

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/apparmor"
	"github.com/docker/libcontainer/console"
	"github.com/docker/libcontainer/label"
	"github.com/docker/libcontainer/mount"
	"github.com/docker/libcontainer/netlink"
	"github.com/docker/libcontainer/network"
	"github.com/docker/libcontainer/security/capabilities"
	"github.com/docker/libcontainer/security/restrict"
	"github.com/docker/libcontainer/utils"
	"github.com/dotcloud/docker/pkg/system"
	"github.com/dotcloud/docker/pkg/user"
)

// TODO(vishh): This is part of the libcontainer API and it does much more than just namespaces related work.
// Move this to libcontainer package.
// Init is the init process that first runs inside a new namespace to setup mounts, users, networking,
// and other options required for the new container.
func Init(container *libcontainer.Config, uncleanRootfs, consolePath string, syncPipe *SyncPipe, args []string) (err error) {
	defer func() {
		if err != nil {
			syncPipe.ReportChildError(err)
		}
	}()

	rootfs, err := utils.ResolveRootfs(uncleanRootfs)
	if err != nil {
		return err
	}

	// clear the current processes env and replace it with the environment
	// defined on the container
	if err := LoadContainerEnvironment(container); err != nil {
		return err
	}

	// We always read this as it is a way to sync with the parent as well
	networkState, err := syncPipe.ReadFromParent()
	if err != nil {
		return err
	}

	if consolePath != "" {
		if err := console.OpenAndDup(consolePath); err != nil {
			return err
		}
	}
	if _, err := system.Setsid(); err != nil {
		return fmt.Errorf("setsid %s", err)
	}
	if consolePath != "" {
		if err := system.Setctty(); err != nil {
			return fmt.Errorf("setctty %s", err)
		}
	}
	if err := setupNetwork(container, networkState); err != nil {
		return fmt.Errorf("setup networking %s", err)
	}
	if err := setupRoute(container); err != nil {
		return fmt.Errorf("setup route %s", err)
	}

	label.Init()

	if err := mount.InitializeMountNamespace(rootfs,
		consolePath,
		(*mount.MountConfig)(container.MountConfig)); err != nil {
		return fmt.Errorf("setup mount namespace %s", err)
	}

	if container.Hostname != "" {
		if err := system.Sethostname(container.Hostname); err != nil {
			return fmt.Errorf("sethostname %s", err)
		}
	}

	runtime.LockOSThread()

	if err := apparmor.ApplyProfile(container.AppArmorProfile); err != nil {
		return fmt.Errorf("set apparmor profile %s: %s", container.AppArmorProfile, err)
	}

	if err := label.SetProcessLabel(container.ProcessLabel); err != nil {
		return fmt.Errorf("set process label %s", err)
	}

	// TODO: (crosbymichael) make this configurable at the Config level
	if container.RestrictSys {
		if err := restrict.Restrict("proc/sys", "proc/sysrq-trigger", "proc/irq", "proc/bus", "sys"); err != nil {
			return err
		}
	}

	userNsEnabled := container.Namespaces["NEWUSER"]
	if userNsEnabled {
		return execUserNs(container, args)
	} else {
		return execDefault(container, args)
	}
}

// Init continues execution for non-userns case in this function.
func execDefault(container *libcontainer.Config, args []string) error {
	pdeathSignal, err := system.GetParentDeathSignal()
	if err != nil {
		return fmt.Errorf("get parent death signal %s", err)
	}

	if err := FinalizeNamespace(container); err != nil {
		return fmt.Errorf("finalize namespace %s", err)
	}

	// Changing user/group clears the parent death
	// signal, so we restore it here.
	if err := RestoreParentDeathSignal(pdeathSignal); err != nil {
		return fmt.Errorf("restore parent death signal %s", err)
	}

	return system.Execv(args[0], args[0:], container.Env)
}

// Get the corresponding hostId for a containerId if specified in the IdMap
func hostIdFromMapping(containerId uint32, idMap []libcontainer.IdMap) (uint32, bool) {
	for _, m := range idMap {
		if (containerId >= m.ContainerId) && (containerId <= (m.ContainerId + m.Size - 1)) {
			hostId := m.HostId + (containerId - m.ContainerId)
			return hostId, true
		}
	}
	return 0, false
}

// Init continues execution for userns case in this function.
func execUserNs(container *libcontainer.Config, args []string) error {
	// Check if the specified user has a mapping provided. If yes,
	// then get the hostUid, hostGid, hostSuppGids corresponding to it.
	uid, gid, suppGroups, err := user.GetUserGroupSupplementary(container.User, syscall.Getuid(), syscall.Getgid())
	if err != nil {
		return fmt.Errorf("get supplementary groups %s", err)
	}

	userNsUid := uint32(uid)
	userNsGid := uint32(gid)
	userNsSuppGids := make([]uint32, len(suppGroups))
	for i, sg := range suppGroups {
		userNsSuppGids[i] = uint32(sg)
	}

	hostUid, found := hostIdFromMapping(userNsUid, container.UidMappings)
	if !found {
		hostUid = OverFlowUid
	}

	hostGid, found := hostIdFromMapping(userNsGid, container.GidMappings)
	if !found {
		hostGid = OverFlowGid
	}

	unmappedSuppGroupAdded := false
	var hostSuppGids []int
	for _, sgid := range userNsSuppGids {
		gid, found := hostIdFromMapping(sgid, container.GidMappings)
		if !found && !unmappedSuppGroupAdded {
			hostSuppGids = append(hostSuppGids, int(OverFlowGid))
			unmappedSuppGroupAdded = true
		} else {
			hostSuppGids = append(hostSuppGids, int(gid))
		}
	}

	pdeathSignal, err := system.GetParentDeathSignal()
	if err != nil {
		return fmt.Errorf("get parent death signal %s", err)
	}

	// Retain capabilities on clone.
	if err := system.Prctl(syscall.PR_SET_SECUREBITS, uintptr(C.SECBIT_KEEP_CAPS|C.SECBIT_NO_SETUID_FIXUP), 0, 0, 0); err != nil {
		return fmt.Errorf("prctl %s", err)
	}

	// Switch to the calculated host uid.
	if err := system.Setuid(int(hostUid)); err != nil {
		return fmt.Errorf("setuid %s", err)
	}

	// Switch to the calculated host gid.
	if err := system.Setgid(int(hostGid)); err != nil {
		return fmt.Errorf("setgid %s", err)
	}

	// Set the calculated supplementary groups.
	if err := system.Setgroups(hostSuppGids); err != nil {
		return fmt.Errorf("setgroups %s", err)
	}

	// Changing user/group clears the parent death
	// signal, so we restore it here.
	if err := RestoreParentDeathSignal(pdeathSignal); err != nil {
		return fmt.Errorf("restore parent death signal %s", err)
	}

	// Switch into a new user namespace.
	rFd, wFd, err := os.Pipe()
	if err != nil {
		return err
	}

	// Lookup the path to the command.
	cmd, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	// Prepare arguments for the raw syscalls.
	var (
		r1         uintptr
		err1       syscall.Errno
		dir        *byte
		rawReadFd  uintptr
		rawWriteFd uintptr
		lzero      uintptr
	)

	argv0p, err := syscall.BytePtrFromString(cmd)
	if err != nil {
		return err
	}

	argvp, err := syscall.SlicePtrFromStrings(args[0:])
	if err != nil {
		return err
	}

	envvp, err := syscall.SlicePtrFromStrings(container.Env)
	if err != nil {
		return err
	}

	if container.WorkingDir != "" {
		dir, err = syscall.BytePtrFromString(container.WorkingDir)
		if err != nil {
			return err
		}
	}

	rawReadFd = rFd.Fd()
	rawWriteFd = wFd.Fd()

	if err := utils.CloseExecFrom(3); err != nil {
		return fmt.Errorf("close open file descriptors %s", err)
	}

	syscall.ForkLock.Lock()
	r1, _, err1 = syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.CLONE_NEWUSER|syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if err1 != 0 {
		return fmt.Errorf("userns clone: %s", err)
	}

	if r1 != 0 {
		// In parent.
		syscall.ForkLock.Unlock()
		proc, err := os.FindProcess(int(r1))
		if err != nil {
			return err
		}

		if err = writeUserMappings(int(r1), container.UidMappings, container.GidMappings); err != nil {
			proc.Kill()
			return fmt.Errorf("Failed to write mappings: %s", err)
		}

		rFd.Close()
		wFd.Close()

		state, err := proc.Wait()
		if err != nil {
			proc.Kill()
			return fmt.Errorf("wait: %s", err)
		}
		os.Exit(state.Sys().(syscall.WaitStatus).ExitStatus())
	}

	// In child.
	// Wait for parent to write the mappings.
	syscall.RawSyscall(syscall.SYS_CLOSE, rawWriteFd, 0, 0)
	_, _, e1 := syscall.RawSyscall(syscall.SYS_READ, rawReadFd, uintptr(unsafe.Pointer(&lzero)), uintptr(1))
	if e1 != 0 {
		return e1
	}

	if dir != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(dir)), 0, 0)
		if err1 != 0 {
			return err1
		}
	}

	_, _, err1 = syscall.RawSyscall(syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0p)),
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envvp[0])))

	return nil
}

// Write UID/GID mappings for a process.
func writeUserMappings(pid int, uidMappings, gidMappings []libcontainer.IdMap) error {
	if len(uidMappings) > 5 || len(gidMappings) > 5 {
		return fmt.Errorf("Only 5 uid/gid mappings are supported by the kernel")
	}

	uidMapStr := make([]string, len(uidMappings))
	for i, um := range uidMappings {
		uidMapStr[i] = fmt.Sprintf("%v %v %v", um.ContainerId, um.HostId, um.Size)
	}

	gidMapStr := make([]string, len(gidMappings))
	for i, gm := range gidMappings {
		gidMapStr[i] = fmt.Sprintf("%v %v %v", gm.ContainerId, gm.HostId, gm.Size)
	}

	uidMap := []byte(strings.Join(uidMapStr, "\n"))
	gidMap := []byte(strings.Join(gidMapStr, "\n"))

	uidMappingsFile := fmt.Sprintf("/proc/%v/uid_map", pid)
	gidMappingsFile := fmt.Sprintf("/proc/%v/gid_map", pid)

	if err := ioutil.WriteFile(uidMappingsFile, uidMap, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(gidMappingsFile, gidMap, 0644); err != nil {
		return err
	}

	return nil
}

// RestoreParentDeathSignal sets the parent death signal to old.
func RestoreParentDeathSignal(old int) error {
	if old == 0 {
		return nil
	}

	current, err := system.GetParentDeathSignal()
	if err != nil {
		return fmt.Errorf("get parent death signal %s", err)
	}

	if old == current {
		return nil
	}

	if err := system.ParentDeathSignal(uintptr(old)); err != nil {
		return fmt.Errorf("set parent death signal %s", err)
	}

	// Signal self if parent is already dead. Does nothing if running in a new
	// PID namespace, as Getppid will always return 0.
	if syscall.Getppid() == 1 {
		return syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
	}

	return nil
}

// SetupUser changes the groups, gid, and uid for the user inside the container
func SetupUser(u string) error {
	uid, gid, suppGids, err := user.GetUserGroupSupplementary(u, syscall.Getuid(), syscall.Getgid())
	if err != nil {
		return fmt.Errorf("get supplementary groups %s", err)
	}
	if err := system.Setgroups(suppGids); err != nil {
		return fmt.Errorf("setgroups %s", err)
	}
	if err := system.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %s", err)
	}
	if err := system.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %s", err)
	}
	return nil
}

// setupVethNetwork uses the Network config if it is not nil to initialize
// the new veth interface inside the container for use by changing the name to eth0
// setting the MTU and IP address along with the default gateway
func setupNetwork(container *libcontainer.Config, networkState *network.NetworkState) error {
	for _, config := range container.Networks {
		strategy, err := network.GetStrategy(config.Type)
		if err != nil {
			return err
		}

		err1 := strategy.Initialize((*network.Network)(config), networkState)
		if err1 != nil {
			return err1
		}
	}
	return nil
}

func setupRoute(container *libcontainer.Config) error {
	for _, config := range container.Routes {
		if err := netlink.AddRoute(config.Destination, config.Source, config.Gateway, config.InterfaceName); err != nil {
			return err
		}
	}
	return nil
}

// FinalizeNamespace drops the caps, sets the correct user
// and working dir, and closes any leaky file descriptors
// before execing the command inside the namespace
func FinalizeNamespace(container *libcontainer.Config) error {
	// Ensure that all non-standard fds we may have accidentally
	// inherited are marked close-on-exec so they stay out of the
	// container
	if err := utils.CloseExecFrom(3); err != nil {
		return fmt.Errorf("close open file descriptors %s", err)
	}

	// drop capabilities in bounding set before changing user
	if err := capabilities.DropBoundingSet(container.Capabilities); err != nil {
		return fmt.Errorf("drop bounding set %s", err)
	}

	// preserve existing capabilities while we change users
	if err := system.SetKeepCaps(); err != nil {
		return fmt.Errorf("set keep caps %s", err)
	}

	if err := SetupUser(container.User); err != nil {
		return fmt.Errorf("setup user %s", err)
	}

	if err := system.ClearKeepCaps(); err != nil {
		return fmt.Errorf("clear keep caps %s", err)
	}

	// drop all other capabilities
	if err := capabilities.DropCapabilities(container.Capabilities); err != nil {
		return fmt.Errorf("drop capabilities %s", err)
	}

	if container.WorkingDir != "" {
		if err := system.Chdir(container.WorkingDir); err != nil {
			return fmt.Errorf("chdir to %s %s", container.WorkingDir, err)
		}
	}

	return nil
}

func LoadContainerEnvironment(container *libcontainer.Config) error {
	os.Clearenv()
	for _, pair := range container.Env {
		p := strings.SplitN(pair, "=", 2)
		if len(p) < 2 {
			return fmt.Errorf("invalid environment '%v'", pair)
		}
		if err := os.Setenv(p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}
