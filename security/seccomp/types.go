package seccomp

// A condition on which to match a syscall
// The condition is considered matched if the following boolean expression
// is true: (Value of Syscall Argument) Operator ValueOne
// As an example, using an operator of > and value of 2 would compare
// whether the value of a syscall argument was greater than 2
type SyscallCondition struct {
	// Which argument of the syscall to inspect. Valid values are 0-6
	Argument uint `json:"argument"`

	// Operator to compare with
	// Valid values are <, <=, ==, >=, >, and |= (masked equality)
	Operator string `json:"operator"`

	// Value to compare given argument against
	ValueOne uint64 `json:"value_one"`

	// Presently only used in masked equality - mask of bits to compare
	ValueTwo uint64 `json:"value_two,omitempty"`
}

// An individual syscall to be blocked by Libseccomp
type BlockedSyscall struct {
	// Name of the syscall
	Name string `json:"name"`

	// Conditions on which to match the syscall.
	// Can be omitted for an unconditional match.
	Conditions []SyscallCondition `json:"conditions,omitempty"`
}

// Overall configuration for Seccomp support
type Config struct {
	// Enable/disable toggle for Libseccomp
	Enable bool `json:"enable"`

	// Toggle whitelisting on. Default is blacklisting - deny given syscalls.
	// if set to true, this reverses this behavior - permit only the given syscalls
	WhitelistToggle bool `json:"whitelist_toggle"`

	// Additional architectures to support in the container.
	// The installed kernel's default architecture is always supported
	Architectures []string `json:"architectures,omitempty"`

	// A list of syscalls to deny (or permit, if WhitelistToggle is set)
	Syscalls []*BlockedSyscall `json:"syscalls"`
}
