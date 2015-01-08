// +build linux,cgo,seccomp

package seccomp

import (
	"fmt"
	"log"
	"strings"
	"syscall"

	libseccomp "github.com/mheon/libseccomp/src/goseccomp"
)

var (
	actAllow libseccomp.ScmpAction = libseccomp.ActAllow
	actDeny  libseccomp.ScmpAction = libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM))
)

// Filters given syscalls in a container, preventing them from being used
// Started in the container init process, and carried over to all child processes
func InitSeccomp(config SeccompConfig) error {
	if !config.Enable {
		return nil
	}

	var defaultAction libseccomp.ScmpAction
	if config.WhitelistToggle {
		defaultAction = actDeny
	} else {
		defaultAction = actAllow
	}

	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return fmt.Errorf("Error creating filter: %s", err)
	}

	// Unset no new privs bit
	if err = filter.SetNoNewPrivsBit(false); err != nil {
		return fmt.Errorf("Error setting no new privileges: %s", err)
	}

	// Add all additional architectures to the filter
	for _, arch := range config.Architectures {
		archConst, err := libseccomp.GetArchFromString(arch)
		if err != nil {
			return fmt.Errorf("Error adding architecture to filter: %s", err)
		}

		if err = filter.AddArch(archConst); err != nil {
			return fmt.Errorf("Error adding architecture %s to filter: %s", arch, err)
		}
	}

	// Add a rule for each syscall
	for _, call := range config.Syscalls {
		if err = blockCall(config.WhitelistToggle, filter, call); err != nil {
			return err
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

// Return an ScmpCompareOp
func compareOpFromString(op string) (libseccomp.ScmpCompareOp, error) {
	switch strings.ToLower(op) {
	case "ne", "!=", "notequal":
		return libseccomp.CompareNotEqual, nil
	case "l", "<", "lessthan":
		return libseccomp.CompareLess, nil
	case "le", "<=", "lessthanorequal":
		return libseccomp.CompareLessOrEqual, nil
	case "eq", "=", "==", "equal":
		return libseccomp.CompareEqual, nil
	case "ge", ">=", "greaterthanorequal":
		return libseccomp.CompareGreaterEqual, nil
	case "g", ">", "greaterthan":
		return libseccomp.CompareGreater, nil
	case "me", "|=", "maskedequal":
		return libseccomp.CompareMaskedEqual, nil
	default:
		return libseccomp.CompareInvalid, fmt.Errorf("Cannot convert string %s into a comparison operator", op)
	}
}

func blockCall(isWhitelist bool, filter *libseccomp.ScmpFilter, call BlockedSyscall) error {
	if len(call.Name) == 0 {
		return fmt.Errorf("Empty string is not a valid syscall!")
	}

	callNum, err := libseccomp.GetSyscallFromName(call.Name)
	if err != nil {
		log.Printf("Error resolving syscall name %s: %s. Ignoring syscall.", call.Name, err)
		return nil
	}

	var action libseccomp.ScmpAction

	if isWhitelist {
		action = actAllow
	} else {
		action = actDeny
	}

	if len(call.Conditions) == 0 {
		if err = filter.AddRule(callNum, action); err != nil {
			return err
		}
	} else {
		conditions := []libseccomp.ScmpCondition{}

		for _, cond := range call.Conditions {
			compareOp, err := compareOpFromString(cond.Operator)
			if err != nil {
				return err
			}

			newCond, err := libseccomp.MakeCondition(cond.Argument, compareOp, cond.ValueOne, cond.ValueTwo)
			if err != nil {
				return err
			}

			conditions = append(conditions, newCond)
		}

		if err = filter.AddRuleConditional(callNum, action, conditions); err != nil {
			return err
		}
	}

	return nil
}
