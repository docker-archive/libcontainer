// +build linux

// Internal functions for libseccomp Go bindings
// No exported functions

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
	"syscall"
)

// Unexported C wrapping code - provides the C-Golang interface
// Get the seccomp header in scope
// Need stdlib.h for free() on cstrings

// #cgo LDFLAGS: -lseccomp
/*
#include <stdlib.h>
#include <seccomp.h>

const uint32_t C_ARCH_NATIVE       = SCMP_ARCH_NATIVE;
const uint32_t C_ARCH_X86          = SCMP_ARCH_X86;
const uint32_t C_ARCH_X86_64       = SCMP_ARCH_X86_64;
const uint32_t C_ARCH_X32          = SCMP_ARCH_X32;
const uint32_t C_ARCH_ARM          = SCMP_ARCH_ARM;

const uint32_t C_ACT_KILL          = SCMP_ACT_KILL;
const uint32_t C_ACT_TRAP          = SCMP_ACT_TRAP;
const uint32_t C_ACT_ERRNO         = SCMP_ACT_ERRNO(0);
const uint32_t C_ACT_TRACE         = SCMP_ACT_TRACE(0);
const uint32_t C_ACT_ALLOW         = SCMP_ACT_ALLOW;

const uint32_t C_ATTRIBUTE_DEFAULT = (uint32_t)SCMP_FLTATR_ACT_DEFAULT;
const uint32_t C_ATTRIBUTE_BADARCH = (uint32_t)SCMP_FLTATR_ACT_BADARCH;
const uint32_t C_ATTRIBUTE_NNP     = (uint32_t)SCMP_FLTATR_CTL_NNP;

const int      C_CMP_NE            = (int)SCMP_CMP_NE;
const int      C_CMP_LT            = (int)SCMP_CMP_LT;
const int      C_CMP_LE            = (int)SCMP_CMP_LE;
const int      C_CMP_EQ            = (int)SCMP_CMP_EQ;
const int      C_CMP_GE            = (int)SCMP_CMP_GE;
const int      C_CMP_GT            = (int)SCMP_CMP_GT;
const int      C_CMP_MASKED_EQ     = (int)SCMP_CMP_MASKED_EQ;

const int      C_VERSION_MAJOR     = SCMP_VER_MAJOR;
const int      C_VERSION_MINOR     = SCMP_VER_MINOR;
const int      C_VERSION_MICRO     = SCMP_VER_MICRO;


// Wrapper to make an array of scmp_arg_cmp structs
void*
make_struct_scmp_arg_cmp_array(unsigned int size)
{
    struct scmp_arg_cmp *s;

    if(size == 0) {
        return NULL;
    }

    s = (struct scmp_arg_cmp *)malloc(size * sizeof(struct scmp_arg_cmp));

    return (void *)s;
}

// Wrapper to fill scmp_arg_cmp structs, so Golang doesn't have to touch them
void
add_struct_scmp_arg_cmp_to_array(
                                    void* array,
                                    unsigned int index,
                                    unsigned int arg,
                                    int compare,
                                    uint64_t a,
                                    uint64_t b
                                )
{
    struct scmp_arg_cmp* s = (struct scmp_arg_cmp *)array;
    s[index].arg = arg;
    s[index].datum_a = a;
    s[index].datum_b = b;
    s[index].op = compare;
}

typedef struct scmp_arg_cmp* scmp_cast_t;
*/
import "C"

// Nonexported types
type scmpFilterAttr uint32

// Nonexported constants

const (
	filterAttrActDefault scmpFilterAttr = iota
	filterAttrActBadArch scmpFilterAttr = iota
	filterAttrNNP        scmpFilterAttr = iota
)

const (
	// An error return from certain libseccomp functions
	scmpError C.int = -1
	// Comparison boundaries to check for architecture validity
	archStart ScmpArch = ArchNative
	archEnd   ScmpArch = ArchARM
	// Comparison boundaries to check for action validity
	actionStart ScmpAction = ActKill
	actionEnd   ScmpAction = ActAllow
	// Comparison boundaries to check for comparison operator validity
	compareOpStart ScmpCompareOp = CompareNotEqual
	compareOpEnd   ScmpCompareOp = CompareMaskedEqual
)

// Nonexported functions

// Init function: Verify library version is appropriate
func init() {
	if C.C_VERSION_MAJOR < 2 || C.C_VERSION_MAJOR == 2 &&
		C.C_VERSION_MINOR < 1 {

		fmt.Fprintf(os.Stderr, "Libseccomp version too low:" +
			"minimum supported is 2.1.0, detected %d.%d.%d", C.C_VERSION_MAJOR,
			C.C_VERSION_MINOR, C.C_VERSION_MICRO)
		os.Exit(-1)
	}
}

// Filter helpers

// Get a raw filter attribute
func (f *ScmpFilter) getFilterAttr(attr scmpFilterAttr, lock bool) (C.uint32_t, error) {
	if lock {
		f.lock.Lock()
		defer f.lock.Unlock()

		if !f.valid {
			return 0x0, fmt.Errorf("Filter is invalid or uninitialized")
		}
	}

	var attribute C.uint32_t

	retCode := C.seccomp_attr_get(f.filterCtx, attr.toNative(), &attribute)
	if retCode != 0 {
		return 0x0, syscall.Errno(-1 * retCode)
	}

	return attribute, nil
}

// Set a raw filter attribute
func (f *ScmpFilter) setFilterAttr(attr scmpFilterAttr, value C.uint32_t) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	retCode := C.seccomp_attr_set(f.filterCtx, attr.toNative(), value)
	if retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Generic add function for filter rules
func (f *ScmpFilter) addRuleGeneric(call ScmpSyscall, action ScmpAction,
	exact bool, conds []ScmpCondition) error {

	f.lock.Lock()
	defer f.lock.Unlock()

	if !f.valid {
		return fmt.Errorf("Filter is invalid or uninitialized")
	}

	// If we have no conditions, this will not allocate memory and returns NULL
	condArray := C.make_struct_scmp_arg_cmp_array(C.uint(len(conds)))
	if len(conds) != 0 {
		defer C.free(condArray)
	}

	// Place all the conditions in the array
	// If the array is empty, does nothing
	for i, cond := range conds {
		// Make sure we provide a valid comparison operator
		if err := sanitizeCompareOp(cond.Op); err != nil {
			return err
		}

		C.add_struct_scmp_arg_cmp_to_array(condArray, C.uint(i),
			C.uint(cond.Argument), cond.Op.toNative(),
			C.uint64_t(cond.Operand1), C.uint64_t(cond.Operand2))
	}

	var retCode C.int

	if exact {
		retCode = C.seccomp_rule_add_exact_array(f.filterCtx,
			action.toNative(), C.int(call), C.uint(len(conds)),
			C.scmp_cast_t(condArray))
	} else {
		retCode = C.seccomp_rule_add_array(f.filterCtx,
			action.toNative(), C.int(call), C.uint(len(conds)),
			C.scmp_cast_t(condArray))
	}

	if syscall.Errno(-1 * retCode) == syscall.EFAULT {
		return fmt.Errorf("Unrecognized syscall")
	} else if retCode != 0 {
		return syscall.Errno(-1 * retCode)
	}

	return nil
}

// Generic Helpers

// Helper - Sanitize Arch token input
func sanitizeArch(in ScmpArch) error {
	if in < archStart || in > archEnd {
		return fmt.Errorf("Unrecognized architecture")
	}

	return nil
}

func sanitizeAction(in ScmpAction) error {
	inTmp := in & 0x0000FFFF
	if inTmp < actionStart || inTmp > actionEnd {
		return fmt.Errorf("Unrecognized action")
	}

	if inTmp != ActTrace && inTmp != ActErrno && (in&0xFFFF0000) != 0 {
		return fmt.Errorf("Lowest 16 bits must be zeroed except for Trace " +
			"and Errno")
	}

	return nil
}

func sanitizeCompareOp(in ScmpCompareOp) error {
	if in < compareOpStart || in > compareOpEnd {
		return fmt.Errorf("Unrecognized comparison operator")
	}

	return nil
}

func archFromNative(a C.uint32_t) (ScmpArch, error) {
	switch a {
	case C.C_ARCH_X86:
		return ArchX86, nil
	case C.C_ARCH_X86_64:
		return ArchAMD64, nil
	case C.C_ARCH_X32:
		return ArchX32, nil
	case C.C_ARCH_ARM:
		return ArchARM, nil
	case C.C_ARCH_NATIVE:
		return ArchNative, nil
	default:
		return 0x0, fmt.Errorf("Unrecognized architecture")
	}
}

// Only use with sanitized arches, no error handling
func (a ScmpArch) toNative() C.uint32_t {
	switch a {
	case ArchX86:
		return C.C_ARCH_X86
	case ArchAMD64:
		return C.C_ARCH_X86_64
	case ArchX32:
		return C.C_ARCH_X32
	case ArchARM:
		return C.C_ARCH_ARM
	case ArchNative:
		return C.C_ARCH_NATIVE
	default:
		return 0x0
	}
}

// Only use with sanitized ops, no error handling
func (a ScmpCompareOp) toNative() C.int {
	switch a {
	case CompareNotEqual:
		return C.C_CMP_NE
	case CompareLess:
		return C.C_CMP_LT
	case CompareLessOrEqual:
		return C.C_CMP_LE
	case CompareEqual:
		return C.C_CMP_EQ
	case CompareGreaterEqual:
		return C.C_CMP_GE
	case CompareGreater:
		return C.C_CMP_GT
	case CompareMaskedEqual:
		return C.C_CMP_MASKED_EQ
	default:
		return 0x0
	}
}

func actionFromNative(a C.uint32_t) (ScmpAction, error) {
	aTmp := a & 0xFFFF
	switch a & 0xFFFF0000 {
	case C.C_ACT_KILL:
		return ActKill, nil
	case C.C_ACT_TRAP:
		return ActTrap, nil
	case C.C_ACT_ERRNO:
		return ActErrno.SetReturnCode(int16(aTmp)), nil
	case C.C_ACT_TRACE:
		return ActTrace.SetReturnCode(int16(aTmp)), nil
	case C.C_ACT_ALLOW:
		return ActAllow, nil
	default:
		return 0x0, fmt.Errorf("Unrecognized action")
	}
}

// Only use with sanitized actions, no error handling
func (a ScmpAction) toNative() C.uint32_t {
	switch a & 0xFFFF {
	case ActKill:
		return C.C_ACT_KILL
	case ActTrap:
		return C.C_ACT_TRAP
	case ActErrno:
		return C.C_ACT_ERRNO | (C.uint32_t(a) >> 16)
	case ActTrace:
		return C.C_ACT_TRACE | (C.uint32_t(a) >> 16)
	case ActAllow:
		return C.C_ACT_ALLOW
	default:
		return 0x0
	}
}

// Internal only, assumes safe action
func (a scmpFilterAttr) toNative() uint32 {
	switch a {
	case filterAttrActDefault:
		return uint32(C.C_ATTRIBUTE_DEFAULT)
	case filterAttrActBadArch:
		return uint32(C.C_ATTRIBUTE_BADARCH)
	case filterAttrNNP:
		return uint32(C.C_ATTRIBUTE_NNP)
	default:
		return 0x0
	}
}
