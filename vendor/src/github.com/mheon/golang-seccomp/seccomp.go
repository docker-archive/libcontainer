// +build linux

// Public API specification for libseccomp Go bindings
// Contains public API, save filter-related functions

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

// Provides bindings for libseccomp, a library wrapping the Linux seccomp
// syscall. Seccomp enables an application to restrict system call use for
// itself and its children.
package seccomp

import (
	"fmt"
	"unsafe"
)

// This file contains the public API of the bindings

// C wrapping code

// #cgo LDFLAGS: -lseccomp
// #include <stdlib.h>
// #include <seccomp.h>
import "C"

// Exported types

// Represents a CPU architecture.
// Seccomp can restrict syscalls on a per-architecture basis.
type ScmpArch uint

// Represents an action to be taken on a filter rule match in libseccomp
type ScmpAction uint

// Represents a comparison operator which can be used in a filter rule
type ScmpCompareOp uint

// Represents a rule in a libseccomp filter context
type ScmpCondition struct {
	Argument uint
	Op       ScmpCompareOp
	Operand1 uint64
	Operand2 uint64
}

// Represents a Linux System Call
type ScmpSyscall int32

// Exported Constants

const (
	// Valid architectures recognized by libseccomp

	// Ensure uninitialized ScmpArch variables are invalid
	ArchInvalid ScmpArch = iota
	// The native architecture of the kernel
	ArchNative ScmpArch = iota
	// 32-bit x86 syscalls
	ArchX86 ScmpArch = iota
	// 64-bit x86-64 syscalls
	ArchAMD64 ScmpArch = iota
	// Syscalls in the kernel x32 ABI
	ArchX32 ScmpArch = iota
	// 32-bit ARM syscalls
	ArchARM ScmpArch = iota
)

const (
	// Supported actions on filter match

	// Ensure uninitialized ScmpAction variables are invalid
	ActInvalid ScmpAction = iota
	// Kill process
	ActKill ScmpAction = iota
	// Throw SIGSYS
	ActTrap ScmpAction = iota
	// The syscall will return an negative error code
	// This code can be set with the SetReturnCode method
	ActErrno ScmpAction = iota
	// Notify tracing processes with given error code
	// This code can be set with the SetReturnCode method
	ActTrace ScmpAction = iota
	// Permit the syscall to continue execution
	ActAllow ScmpAction = iota
)

const (
	// These are comparison operators used in conditional seccomp rules

	// Ensure uninitialized ScmpCompareOp variables are invalid
	CompareInvalid      ScmpCompareOp = iota
	CompareNotEqual     ScmpCompareOp = iota
	CompareLess         ScmpCompareOp = iota
	CompareLessOrEqual  ScmpCompareOp = iota
	CompareEqual        ScmpCompareOp = iota
	CompareGreaterEqual ScmpCompareOp = iota
	CompareGreater      ScmpCompareOp = iota
	CompareMaskedEqual  ScmpCompareOp = iota
)

// Helpers for types

// Returns a string representation of an architecture constant
func (a ScmpArch) String() string {
	switch a {
	case ArchX86:
		return "x86"
	case ArchAMD64:
		return "amd64"
	case ArchX32:
		return "x32"
	case ArchARM:
		return "arm"
	case ArchNative:
		return "native"
	case ArchInvalid:
		return "Invalid architecture"
	default:
		return "Unknown architecture"
	}
}

// Returns a string representation of a comparison operator constant
func (a ScmpCompareOp) String() string {
	switch a {
	case CompareNotEqual:
		return "Not equal"
	case CompareLess:
		return "Less than"
	case CompareLessOrEqual:
		return "Less than or equal to"
	case CompareEqual:
		return "Equal"
	case CompareGreaterEqual:
		return "Greater than or equal to"
	case CompareGreater:
		return "Greater than"
	case CompareMaskedEqual:
		return "Masked equality"
	case CompareInvalid:
		return "Invalid comparison operator"
	default:
		return "Unrecognized comparison operator"
	}
}

// Returns a string representation of a seccomp match action
func (a ScmpAction) String() string {
	switch a & 0xFFFF {
	case ActKill:
		return "Action: Kill Process"
	case ActTrap:
		return "Action: Send SIGSYS"
	case ActErrno:
		return fmt.Sprintf("Action: Return error code %d", (a >> 16))
	case ActTrace:
		return fmt.Sprintf("Action: Notify tracing processes with code %d",
			(a >> 16))
	case ActAllow:
		return "Action: Allow system call"
	default:
		return "Unrecognized Action"
	}
}

// Add a return code to a supporting ScmpAction, clearing any existing code
// Only valid on ActErrno and ActTrace. Takes no action otherwise.
// Accepts 16-bit return code as argument.
// Returns a valid ScmpAction of the original type with the new error code set.
func (a ScmpAction) SetReturnCode(code int16) ScmpAction {
	aTmp := a & 0x0000FFFF
	if aTmp == ActErrno || aTmp == ActTrace {
		return (aTmp | (ScmpAction(code)&0xFFFF)<<16)
	}
	return a
}

// Get the return code of an ScmpAction
func (a ScmpAction) GetReturnCode() int16 {
	return int16(a >> 16)
}

// Syscall functions

// Get the name of a syscall from its number.
// Acts on any syscall number.
// Returns either a string containing the name of the syscall, or an error.
func (s ScmpSyscall) GetName() (string, error) {
	return s.GetNameByArch(ArchNative)
}

// Get the name of a syscall from its number for a given architecture.
// Acts on any syscall number.
// Accepts a valid architecture constant.
// Returns either a string containing the name of the syscall, or an error.
// if the syscall is unrecognized or an issue occurred.
func (s ScmpSyscall) GetNameByArch(arch ScmpArch) (string, error) {
	if err := sanitizeArch(arch); err != nil {
		return "", err
	}

	cString := C.seccomp_syscall_resolve_num_arch(arch.toNative(), C.int(s))
	if cString == nil {
		return "", fmt.Errorf("Could not resolve syscall name")
	}
	defer C.free(unsafe.Pointer(cString))

	finalStr := C.GoString(cString)
	return finalStr, nil
}

// Get the number of a syscall by name on the kernel's native architecture.
// Accepts a string containing the name of a syscall.
// Returns the number of the syscall, or an error if no syscall with that name
// was found.
func GetSyscallFromName(name string) (ScmpSyscall, error) {
	cString := C.CString(name)
	defer C.free(unsafe.Pointer(cString))

	result := C.seccomp_syscall_resolve_name(cString)
	if result == scmpError {
		return 0, fmt.Errorf("Could not resolve name to syscall")
	}

	return ScmpSyscall(result), nil
}

// Get the number of a syscall by name for a given architecture's ABI.
// Accepts the name of a syscall and an architecture constant.
// Returns the number of the syscall, or an error if an invalid architecture is
// passed or a syscall with that name was not found.
func GetSyscallFromNameByArch(name string, arch ScmpArch) (ScmpSyscall, error) {
	if err := sanitizeArch(arch); err != nil {
		return 0, err
	}

	cString := C.CString(name)
	defer C.free(unsafe.Pointer(cString))

	result := C.seccomp_syscall_resolve_name_arch(arch.toNative(), cString)
	if result == scmpError {
		return 0, fmt.Errorf("Could not resolve name to syscall")
	}

	return ScmpSyscall(result), nil
}

// Make a new condition to attach to a filter rule.
// Associated rules will only match if this condition is true.
// Accepts the number the argument we are checking, and a comparison operator
// and value to compare to.
// The rule will match if argument $arg (zero-indexed) of the syscall is
// $COMPARE_OP the provided comparison value.
// For example, in the less than or equal case, if the syscall argument was
// 0 and the value provided was 1, the condition would match, as 0 is less
// than or equal to 1.
// Return either an error on bad argument or a valid ScmpCondition struct.
func MakeCondition(arg uint, comparison ScmpCompareOp, value uint64) (*ScmpCondition, error) {

	if comparison == CompareMaskedEqual {
		return nil, fmt.Errorf("Masked comparisons must use" +
			"MakeConditionMasked!")
	} else if comparison == CompareInvalid {
		return nil, fmt.Errorf("Invalid comparison operator!")
	} else if arg > 5 {
		return nil, fmt.Errorf("Syscalls only have up to 6 arguments!")
	}

	condStruct := new(ScmpCondition)

	condStruct.Argument = arg
	condStruct.Op = comparison
	condStruct.Operand1 = value

	return condStruct, nil
}

// Functions similarly to MakeCondition(), but accepts an additional parameter,
// a mask - only bits set to 1 in the mask are compared by this rule.
// Only works with Masked comparison operators (at present, only
// CompareMaskedEquals).
func MakeConditionMasked(arg uint, comparison ScmpCompareOp, value uint64,
	mask uint64) (*ScmpCondition, error) {

	if comparison != CompareMaskedEqual {
		return nil, fmt.Errorf("Only masked comparisons use" +
			"MakeConditionMasked!")
	} else if arg > 5 {
		return nil, fmt.Errorf("Syscalls only have up to 6 arguments!")
	}

	condStruct := new(ScmpCondition)

	condStruct.Argument = arg
	condStruct.Op = comparison
	condStruct.Operand1 = mask
	condStruct.Operand2 = value

	return condStruct, nil
}

// Utility Functions

// Returns architecture token representing the native kernel architecture
func GetNativeArch() (ScmpArch, error) {
	arch := C.seccomp_arch_native()

	return archFromNative(arch)
}
