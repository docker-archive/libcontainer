package main

import (
	"syscall"

	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/security/seccomp"
)

var profiles = map[string]*securityProfile{
	"high":   highProfile,
	"medium": mediumProfile,
	"low":    lowProfile,
}

type securityProfile struct {
	Capabilities    []string         `json:"capabilities"`
	ApparmorProfile string           `json:"apparmor_profile"`
	MountLabel      string           `json:"mount_label"`
	ProcessLabel    string           `json:"process_label"`
	Rlimits         []configs.Rlimit `json:"rlimits"`
	Seccomp         *seccomp.Config  `json:"seccomp"`
}

// this should be a runtime config that is not able to do things like apt-get or yum install.
var highProfile = &securityProfile{
	Capabilities: []string{
		"NET_BIND_SERVICE",
		"KILL",
		"AUDIT_WRITE",
	},
	Rlimits: []configs.Rlimit{
		{
			Type: syscall.RLIMIT_NOFILE,
			Hard: 1024,
			Soft: 1024,
		},
	},
	// http://man7.org/linux/man-pages/man2/syscalls.2.html
	Seccomp: &seccomp.Config{
		Enable: true,
		WhitelistToggle: false,
		Architectures: []string{},
		Syscalls: []*seccomp.BlockedSyscall{
			{
				Name: "capset", // http://man7.org/linux/man-pages/man2/capset.2.html
			},
			{
				Name: "unshare", // http://man7.org/linux/man-pages/man2/unshare.2.html
			},
			{
				Name: "setns",
			},
			{
				Name: "mount", // http://man7.org/linux/man-pages/man2/mount.2.html
			},
			{
				Name: "umount2", // http://man7.org/linux/man-pages/man2/umount.2.html
			},
			{
				Name: "create_module", // http://man7.org/linux/man-pages/man2/create_module.2.html
			},
			{
				Name: "delete_module", // http://man7.org/linux/man-pages/man2/delete_module.2.html
			},
			{
				Name: "chmod", // http://man7.org/linux/man-pages/man2/chmod.2.html
			},
			{
				Name: "chown", // http://man7.org/linux/man-pages/man2/chown.2.html
			},
			{
				Name: "link", // http://man7.org/linux/man-pages/man2/link.2.html
			},
			{
				Name: "linkat", // http://man7.org/linux/man-pages/man2/linkat.2.html
			},
			{
				Name: "unlink", // http://man7.org/linux/man-pages/man2/unlink.2.html
			},
			{
				Name: "unlinkat", // http://man7.org/linux/man-pages/man2/unlinkat.2.html
			},
			{
				Name: "chroot", // http://man7.org/linux/man-pages/man2/chroot.2.html
			},
			{
				Name: "kexec_load", // http://man7.org/linux/man-pages/man2/kexec_load.2.html
			},
			{
				Name: "setdomainname", // http://man7.org/linux/man-pages/man2/setdomainname.2.html
			},
			{
				Name: "sethostname", // http://man7.org/linux/man-pages/man2/sethostname.2.html
			},
			{
				Name: "clone",
				Conditions: []seccomp.SyscallCondition{
					{
						Argument: 0,
						Operator: "|=",
						ValueOne: syscall.CLONE_NEWUSER,
						ValueTwo: syscall.CLONE_NEWUSER,
					},
				},
			},
		},
	},
}

// This is a medium level profile that should be able to do things like installing from
// apt-get or yum.
var mediumProfile = &securityProfile{
	Capabilities: []string{
		"CHOWN",
		"DAC_OVERRIDE",
		"FSETID",
		"FOWNER",
		"SETGID",
		"SETUID",
		"SETFCAP",
		"SETPCAP",
		"NET_BIND_SERVICE",
		"KILL",
		"AUDIT_WRITE",
	},
	Rlimits: []configs.Rlimit{
		{
			Type: syscall.RLIMIT_NOFILE,
			Hard: 1024,
			Soft: 1024,
		},
	},
	// http://man7.org/linux/man-pages/man2/syscalls.2.html
	Seccomp: &seccomp.Config{
		Enable: true,
		WhitelistToggle: false,
		Architectures: []string{},
		Syscalls: []*seccomp.BlockedSyscall{
			{
				Name: "unshare", // http://man7.org/linux/man-pages/man2/unshare.2.html
			},
			{
				Name: "setns",
			},
			{
				Name: "mount", // http://man7.org/linux/man-pages/man2/mount.2.html
			},
			{
				Name: "umount2", // http://man7.org/linux/man-pages/man2/umount.2.html
			},
			{
				Name: "chroot", // http://man7.org/linux/man-pages/man2/chroot.2.html
			},
			{
				Name: "create_module", // http://man7.org/linux/man-pages/man2/create_module.2.html
			},
			{
				Name: "delete_module", // http://man7.org/linux/man-pages/man2/delete_module.2.html
			},
			{
				Name: "kexec_load", // http://man7.org/linux/man-pages/man2/kexec_load.2.html
			},
			{
				Name: "setdomainname", // http://man7.org/linux/man-pages/man2/setdomainname.2.html
			},
			{
				Name: "sethostname", // http://man7.org/linux/man-pages/man2/sethostname.2.html
			},
			{
				Name: "clone",
				Conditions: []seccomp.SyscallCondition{
					{
						Argument: 0,
						Operator: "|=",
						ValueOne: syscall.CLONE_NEWUSER,
						ValueTwo: syscall.CLONE_NEWUSER,
					},
				},
			},
		},
	},
}

var lowProfile = &securityProfile{
	Capabilities: []string{
		"CHOWN",
		"DAC_OVERRIDE",
		"FSETID",
		"FOWNER",
		"SETGID",
		"SETUID",
		"SYS_CHROOT",
		"SETFCAP",
		"SETPCAP",
		"NET_BIND_SERVICE",
		"KILL",
		"AUDIT_WRITE",
	},
	Rlimits: []configs.Rlimit{
		{
			Type: syscall.RLIMIT_NOFILE,
			Hard: 1024,
			Soft: 1024,
		},
	},
	// http://man7.org/linux/man-pages/man2/syscalls.2.html
	Seccomp: &seccomp.Config{
		Enable: true,
		WhitelistToggle: false,
		Architectures: []string{},
		Syscalls: []*seccomp.BlockedSyscall{
			{
				Name: "unshare", // http://man7.org/linux/man-pages/man2/unshare.2.html
			},
			{
				Name: "setns",
			},
			{
				Name: "mount", // http://man7.org/linux/man-pages/man2/mount.2.html
			},
			{
				Name: "umount2", // http://man7.org/linux/man-pages/man2/umount.2.html
			},
			{
				Name: "create_module", // http://man7.org/linux/man-pages/man2/create_module.2.html
			},
			{
				Name: "delete_module", // http://man7.org/linux/man-pages/man2/delete_module.2.html
			},
			{
				Name: "kexec_load", // http://man7.org/linux/man-pages/man2/kexec_load.2.html
			},
			{
				Name: "clone",
				Conditions: []seccomp.SyscallCondition{
					{
						Argument: 0,
						Operator: "|=",
						ValueOne: syscall.CLONE_NEWUSER,
						ValueTwo: syscall.CLONE_NEWUSER,
					},
				},
			},
		},
	},
}
