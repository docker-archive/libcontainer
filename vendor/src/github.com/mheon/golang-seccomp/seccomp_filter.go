// +build linux

// Public API specification for libseccomp Go bindings
// Contains public filter API

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

package seccomp

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

// #cgo LDFLAGS: -lseccomp
// #include <stdlib.h>
// #include <seccomp.h>
import "C"

// Public Filter API

// Represents a filter context in libseccomp.
// A filter context is initially empty. Rules can be added to it, and it can
// then be loaded into the kernel.
type ScmpFilter struct {
	filterCtx C.scmp_filter_ctx
	valid     bool
	lock      sync.Mutex
}

// Create a new filter context.
// Accepts a default action to be taken for syscalls which match no rules in
// the filter.
// Returns a reference to a valid filter context, or nil and an error if the
// filter context could not be created or an invalid default action was given.
func NewFilter(defaultAction ScmpAction) (*ScmpFilter, error) {
	if err := sanitizeAction(defaultAction); err != nil {
		return nil, err
	}

	fPtr := C.seccomp_init(defaultAction.toNative())
	if fPtr == nil {
		return nil, fmt.Errorf("Could not create filter")
	}

	filter := new(ScmpFilter)
	filter.filterCtx = fPtr
	filter.valid = true

	return filter, nil
}

// Determine whether a filter context is valid to use.
// Some operations (Release and Merge) render filter contexts invalid and
// consequently prevent further use.
func (f *ScmpFilter) IsValid() bool {
	f.lock.Lock()
	defer f.lock.Unlock()

	return f.valid
}

// Reset a filter context, removing all its existing state.
// Accepts a new default action to be taken for syscalls which do not match.
// Returns an error if the filter or action provided are invalid.
func (f *ScmpFilter) Reset(defaultAction ScmpAction) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := sanitizeAction(defaultAction); err != nil {
		return err
	} else if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	retCode := C.seccomp_reset(f.filterCtx, defaultAction.toNative())
	if retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Releases a filter context, freeing its memory. Should be called after
// loading into the kernel, when the filter is no longer needed.
// After calling this function, the given filter is no longer valid and cannot
// be used.
func (f *ScmpFilter) Release() {
	f.lock.Lock()
	defer f.lock.Unlock()

	if !f.valid {
		return
	}

	f.valid = false
	C.seccomp_release(f.filterCtx)
}

// Merge two filter contexts.
// The source filter src will be released as part of the process, and will no
// longer be usable or valid after this call.
// To be merged, filters must NOT share any architectures, and all their
// attributes must match.
// The filter src will be merged into the filter this is called on.
// The architectures of the src filter not present in the destination, and all
// associated rules, will be added to the destination.
// Returns an error if merging the filters failed.
func (f *ScmpFilter) Merge(src *ScmpFilter) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	src.lock.Lock()
	defer src.lock.Unlock()

	if !src.valid || !f.valid {
		return fmt.Errorf(
			"One or more of the filter contexts is invalid or uninitialized")
	}

	// Check to ensure filter attributes match

	default1, err := f.getFilterAttr(filterAttrActDefault, false)
	if err != nil {
		return err
	}

	default2, err := src.getFilterAttr(filterAttrActDefault, false)
	if err != nil {
		return err
	}

	if default1 != default2 {
		return fmt.Errorf("Default Action on both filters must match")
	}

	badArch1, err := f.getFilterAttr(filterAttrActBadArch, false)
	if err != nil {
		return err
	}

	badArch2, err := src.getFilterAttr(filterAttrActBadArch, false)
	if err != nil {
		return err
	}

	if badArch1 != badArch2 {
		return fmt.Errorf("Bad Architecture Action on both filters must match")
	}

	nnp1, err := f.getFilterAttr(filterAttrNNP, false)
	if err != nil {
		return err
	}

	nnp2, err := src.getFilterAttr(filterAttrNNP, false)
	if err != nil {
		return err
	}

	if nnp1 != nnp2 {
		return fmt.Errorf("No new privileges bit on both filters must match")
	}

	// Merge the filters
	if retCode := C.seccomp_merge(f.filterCtx, src.filterCtx); retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	src.valid = false

	return nil
}

// Check if an architecture is present in a filter.
// If a filter contains an architecture, it uses its default action for
// syscalls which do not match rules in it, and its rules can match syscalls
// for that ABI.
// If a filter does not contain an architecture, all syscalls made to that
// kernel ABI will fail with the filter's default Bad Architecture Action
// (by default, killing the process).
// Accepts an architecture constant.
// Returns true if the architecture is present in the filter, false otherwise,
// and an error on an invalid filter context, architecture constant, or an
// issue with the call to libseccomp.
func (f *ScmpFilter) IsArchPresent(arch ScmpArch) (bool, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := sanitizeArch(arch); err != nil {
		return false, err
	} else if !f.valid {
		return false, fmt.Errorf("Filter is invalid or uninitialized")
	}

	retCode := C.seccomp_arch_exist(f.filterCtx, arch.toNative())
	if syscall.Errno(-1*retCode) == syscall.EEXIST {
		// -EEXIST is "arch not present"
		return false, nil
	} else if retCode != 0 {
		return false, syscall.Errno(-1 * retCode)
	}

	return true, nil
}

// Add an architecture to the filter.
// Accepts an architecture constant.
// Returns an error on invalid filter context or architecture token, or an
// issue with the call to libseccomp.
func (f *ScmpFilter) AddArch(arch ScmpArch) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := sanitizeArch(arch); err != nil {
		return err
	} else if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	// Libseccomp returns -EEXIST if the specified architecture is already
	// present. Succeed silently in this case, as it's not fatal, and the
	// architecture is present already.
	retCode := C.seccomp_arch_add(f.filterCtx, arch.toNative())
	if retCode != 0 && syscall.Errno(-1 * retCode) != syscall.EEXIST {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Remove an architecture from the filter.
// Accepts an architecture constant.
// Returns an error on invalid filter context or architecture token, or an
// issue with the call to libseccomp.
func (f *ScmpFilter) RemoveArch(arch ScmpArch) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := sanitizeArch(arch); err != nil {
		return err
	} else if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	// Similar to AddArch, -EEXIST is returned if the arch is not present
	// Succeed silently in that case, this is not fatal and the architecture
	// is not present in the filter after RemoveArch
	retCode := C.seccomp_arch_remove(f.filterCtx, arch.toNative())
	if retCode != 0 && syscall.Errno(-1 * retCode) != syscall.EEXIST {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Load a filter context into the kernel.
// Returns an error if the filter context is invalid or the syscall failed.
func (f *ScmpFilter) Load() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	if retCode := C.seccomp_load(f.filterCtx); retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Returns the default action taken on a syscall which does not match a rule in
// the filter, or an error if an issue was encountered retrieving the value.
func (f *ScmpFilter) GetDefaultAction() (ScmpAction, error) {
	action, err := f.getFilterAttr(filterAttrActDefault, true)
	if err != nil {
		return 0x0, err
	}

	return actionFromNative(action)
}

// Returns the default action taken on a syscall for an architecture not in the
// filter, or an error if an issue was encountered retrieving the value.
func (f *ScmpFilter) GetBadArchAction() (ScmpAction, error) {
	action, err := f.getFilterAttr(filterAttrActBadArch, true)
	if err != nil {
		return 0x0, err
	}

	return actionFromNative(action)
}

// Returns the current state the No New Privileges bit will be set to on the
// filter being loaded, or an error if an issue was encountered retrieving the
// value.
// The No New Privileges bit tells the kernel that new processes run with exec()
// cannot gain more privileges than the process that ran exec().
// For example, a process with No New Privileges set would be unable to exec
// setuid/setgid executables.
func (f *ScmpFilter) GetNoNewPrivsBit() (bool, error) {
	noNewPrivs, err := f.getFilterAttr(filterAttrNNP, true)
	if err != nil {
		return false, err
	}

	if noNewPrivs == 0 {
		return false, nil
	}

	return true, nil
}

// Set the default action taken on a syscall for an architecture not in the
// filter, or an error if an issue was encountered setting the value.
func (f *ScmpFilter) SetBadArchAction(action ScmpAction) error {
	if err := sanitizeAction(action); err != nil {
		return err
	}

	return f.setFilterAttr(filterAttrActBadArch, action.toNative())
}

// Set the state of the No New Privileges bit, which will be applied on filter
// load, or an error if an issue was encountered setting the value.
// Filters with No New Privileges set to 0 can only be loaded with the
// CAP_SYS_ADMIN privilege.
func (f *ScmpFilter) SetNoNewPrivsBit(state bool) error {
	var toSet C.uint32_t = 0x0

	if state {
		toSet = 0x1
	}

	return f.setFilterAttr(filterAttrNNP, toSet)
}

// Set a syscall's priority.
// This provides a hint to the filter generator in libseccomp about the
// importance of this syscall. High-priority syscalls are placed
// first in the filter code, and incur less overhead (at the expense of
// lower-priority syscalls).
func (f *ScmpFilter) SetSyscallPriority(call ScmpSyscall, priority uint8) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	if retCode := C.seccomp_syscall_priority(f.filterCtx, C.int(call),
		C.uint8_t(priority)); retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Add a single rule for an unconditional action on a syscall.
// Accepts the number of the syscall and the action to be taken on the call
// being made.
// Returns an error if an issue was encountered adding the rule.
func (f *ScmpFilter) AddRule(call ScmpSyscall, action ScmpAction) error {
	return f.addRuleGeneric(call, action, false, nil)
}

// Add a single rule for an unconditional action on a syscall.
// Accepts the number of the syscall and the action to be taken on the call
// being made.
// No modifications will be made to the rule, and it will fail to add if it
// cannot be applied to the current architecture without modification.
// The rule will function exactly as described, but it may not function identically
// (or be able to be applied to) all architectures.
// Returns an error if an issue was encountered adding the rule.
func (f *ScmpFilter) AddRuleExact(call ScmpSyscall, action ScmpAction) error {
	return f.addRuleGeneric(call, action, true, nil)
}

// Add a single rule for a conditional action on a syscall.
// Returns an error if an issue was encountered adding the rule.
// All conditions must match for the rule to match.
func (f *ScmpFilter) AddRuleConditional(call ScmpSyscall, action ScmpAction,
	conds []ScmpCondition) error {

	return f.addRuleGeneric(call, action, false, conds)
}

// Add a single rule for a conditional action on a syscall.
// No modifications will be made to the rule, and it will fail to add if it
// cannot be applied to the current architecture without modification.
// The rule will function exactly as described, but it may not function identically
// (or be able to be applied to) all architectures.
// Returns an error if an issue was encountered adding the rule.
func (f *ScmpFilter) AddRuleConditionalExact(call ScmpSyscall,
	action ScmpAction, conds []ScmpCondition) error {

	return f.addRuleGeneric(call, action, true, conds)
}

// Output PFC-formatted, human-readable dump of a filter context's rules to a
// file.
// Accepts file to write to (must be open for writing).
// Returns an error if writing to the file fails.
func (f *ScmpFilter) ExportPFC(file *os.File) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	fd := file.Fd()

	if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	if retCode := C.seccomp_export_pfc(f.filterCtx, C.int(fd)); retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Output Berkeley Packet Filter-formatted, kernel-readable dump of a filter
// context's rules to a file.
// Accepts file to write to (must be open for writing).
// Returns an error if writing to the file fails.
func (f *ScmpFilter) ExportBPF(file *os.File) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	fd := file.Fd()

	if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	if retCode := C.seccomp_export_bpf(f.filterCtx, C.int(fd)); retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}
