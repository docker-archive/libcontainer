package libcontainer

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/docker/libcontainer/security/capabilities"
	"github.com/docker/libcontainer/system"
	"github.com/docker/libcontainer/utils"
	"github.com/dotcloud/docker/pkg/user"
)

// getNamespaceFlags parses the container's Namespaces options to set the correct
// flags on clone, unshare, and setns
func getNamespaceFlags(namespaces map[string]bool) (flag int) {
	for key, enabled := range namespaces {
		if enabled {
			if ns := getNamespace(key); ns != nil {
				flag |= ns.Value
			}
		}
	}

	return flag
}

// restoreParentDeathSignal sets the parent death signal to old.
func restoreParentDeathSignal(old int) error {
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

// setupUser changes the groups, gid, and uid for the user inside the container
func setupUser(u string) error {
	uid, gid, suppGids, err := user.GetUserGroupSupplementary(u, syscall.Getuid(), syscall.Getgid())
	if err != nil {
		return fmt.Errorf("get supplementary groups %s", err)
	}

	if err := syscall.Setgroups(suppGids); err != nil {
		return fmt.Errorf("setgroups %s", err)
	}

	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %s", err)
	}

	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %s", err)
	}

	return nil
}

// FinalizeNamespace drops the caps, sets the correct user
// and working dir, and closes any leaky file descriptors
// before execing the command inside the namespace
func finalizeNamespace(container *Config) error {
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

	if err := setupUser(container.User); err != nil {
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
		if err := syscall.Chdir(container.WorkingDir); err != nil {
			return fmt.Errorf("chdir to %s %s", container.WorkingDir, err)
		}
	}

	return nil
}

func replaceEnvironment(process *ProcessConfig) error {
	for _, pair := range process.Env {
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
