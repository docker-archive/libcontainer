package seccomp

type SyscallCondition struct {
	Argument uint   `json:"argument"`
	Operator string `json:"operator"`
	ValueOne uint64 `json:"value_one"`
	ValueTwo uint64 `json:"value_two,omitempty"`
}

type BlockedSyscall struct {
	Name       string             `json:"name,"`
	Conditions []SyscallCondition `json:"conditions,omitempty"`
}

type SeccompConfig struct {
	Enable          bool             `json:"enable"`
	WhitelistToggle bool             `json:"whitelist_toggle"`
	Architectures   []string         `json:"architectures,omitempty"`
	Syscalls        []BlockedSyscall `json:"syscalls"`
}
