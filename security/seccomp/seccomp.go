// +build linux,cgo,seccomp

package seccomp

import (
	"fmt"
	"syscall"

	"sourceforge.net/seccomp"
)

type Seccomp struct {
	Architecture string
	Syscall      string
	Args         []string
}

var (
	// Match action: deny a syscall with -EPERM return code
	actDeny seccomp.ScmpAction = seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM))
)

// Filters given syscalls in a container, preventing them from being used
// Started in the container init process, and carried over to all child processes
func InitSeccomp(secomps []Seccomp) error {
	if len(secomps) == 0 {
		return nil
	}

	archNative, err := seccomp.GetNativeArch()
	if err != nil {
		return fmt.Errorf("Error getting native architecture: %s", err)
	}

	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return fmt.Errorf("Error creating filter: %s", err)
	}

	// Unset no new privs bit
	if err = filter.SetNoNewPrivsBit(false); err != nil {
		return fmt.Errorf("Error setting no new privileges: %s", err)
	}

	// If native arch is AMD64, add X86 to filter
	if archNative == seccomp.ArchAMD64 {
		if err = filter.AddArch(seccomp.ArchX86); err != nil {
			return fmt.Errorf("Error adding x86 arch to filter: %s", err)
		}
	}

	for _, call := range secomps {
		if len(call.Architecture) > 0 {
			archNum, err := seccomp.GetArchFromName(call.Architecture)
			if err != nil {
				return fmt.Errorf("Could not resolve Archietecture name %q: %s", call.Architecture, err)
			}
			if err = filter.AddArch(archNum); err != nil {
				return fmt.Errorf("Error adding %q arch to filter: %s", call.Architecture, err)
			}
			continue
		}
		if len(call.Syscall) == 0 {
			return fmt.Errorf("Empty string is not a valid syscall!")
		}

		callNum, err := seccomp.GetSyscallFromName(call.Syscall)
		if err != nil {
			return fmt.Errorf("Could not resolve syscall name %s: %s", call.Syscall, err)
		}

		if len(call.Args) == 0 {
			if err = filter.AddRule(callNum, actDeny); err != nil {
				return fmt.Errorf("Error adding rule to filter for syscall %s: %s", call, err)
			}
		}
	}

	if err != nil {
		return fmt.Errorf("Error initializing filter: %s", err)
	}

	if err = filter.Load(); err != nil {
		return fmt.Errorf("Error loading seccomp filter into kernel: %s", err)
	}

	return nil
}
