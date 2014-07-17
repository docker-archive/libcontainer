package libcontainer

import (
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/mount"
	"github.com/docker/libcontainer/network"
)

type (
	MountConfig mount.MountConfig
	Network     network.Network
)

// Config defines configuration options for executing a process inside a contained environment.
type Config struct {
	// Rootfs is the container's root filesystem used as the jail for the container
	Rootfs string `json:"rootfs,omitempty"`

	// Mount specific options.
	MountConfig *MountConfig `json:"mount_config,omitempty"`

	// Hostname optionally sets the container's hostname if provided
	Hostname string `json:"hostname,omitempty"`

	// User will set the uid and gid of the executing process running inside the container
	User string `json:"user,omitempty"`

	// WorkingDir will change the processes current working directory inside the container's rootfs
	WorkingDir string `json:"working_dir,omitempty"`

	// Namespaces specifies the container's namespaces that it should setup when cloning the init process
	// If a namespace is not provided that namespace is shared from the container's parent process
	Namespaces map[string]bool `json:"namespaces,omitempty"`

	// Capabilities specify the capabilities to keep when executing the process inside the container
	// All capbilities not specified will be dropped from the processes capability mask
	Capabilities []string `json:"capabilities,omitempty"`

	// Networks specifies the container's network setup to be created
	Networks []*Network `json:"networks,omitempty"`

	// Routes can be specified to create entries in the route table as the container is started
	Routes []*Route `json:"routes,omitempty"`

	// Cgroups specifies specific cgroup settings for the various subsystems that the container is
	// placed into to limit the resources the container has available
	Cgroups *cgroups.Cgroup `json:"cgroups,omitempty"`

	// AppArmorProfile specifies the profile to apply to the process running in the container and is
	// change at the time the process is execed
	AppArmorProfile string `json:"apparmor_profile,omitempty"`

	// ProcessLabel specifies the label to apply to the process running in the container.  It is
	// commonly used by selinux
	ProcessLabel string `json:"process_label,omitempty"`

	// RestrictSys will remount /proc/sys, /sys, and mask over sysrq-trigger as well as /proc/irq and
	// /proc/bus
	RestrictSys bool `json:"restrict_sys,omitempty"`
}
