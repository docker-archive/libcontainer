package libcontainer

import (
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/mount"
	"github.com/docker/libcontainer/network"
)

type MountConfig mount.MountConfig

type Network network.Network

// Config defines configuration options for executing a process inside a contained environment.
type Config struct {
	// Mount specific options.
	MountConfig *MountConfig `json:"mount_config,omitempty"`

	// Hostname optionally sets the container's hostname if provided
	Hostname string `json:"hostname,omitempty"`

	// User will set the uid and gid of the executing process running inside the container
	User string `json:"user,omitempty"`

	// WorkingDir will change the processes current working directory inside the container's rootfs
	WorkingDir string `json:"working_dir,omitempty"`

	// Env will populate the processes environment with the provided values
	// Any values from the parent processes will be cleared before the values
	// provided in Env are provided to the process
	Env []string `json:"environment,omitempty"`

	// Tty when true will allocate a pty slave on the host for access by the container's process
	// and ensure that it is mounted inside the container's rootfs
	Tty bool `json:"tty,omitempty"`

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

	// Context is a generic key value format that allows for additional settings to be passed
	// on the container's creation
	// This is commonly used to specify apparmor profiles, selinux labels, and different restrictions
	// placed on the container's processes
	// TODO(vishh): Avoid overloading this field with params for different subsystems. Strongtype this.
	Context map[string]string `json:"context,omitempty"`

	// UserNsUid specifies the uid to run as when user namespace mappings are specified
	UserNsUid uint32 `json:"user_ns_uid,omitempty"`

	// UserNsGid specifies the gid to run as when user namespace mappings are specified
	UserNsGid uint32 `json:"user_ns_gid,omitempty"`

	// UidMappings is a string array of uid mappings for user namespaces
	UidMappings []IdMap `json:"uid_mappings,omitempty"`

	// GidMappings is a string array of gid mappings for user namespaces
	GidMappings []IdMap `json:"gid_mappings,omitempty"`
}

// Routes can be specified to create entries in the route table as the container is started
//
// All of destination, source, and gateway should be either IPv4 or IPv6.
// One of the three options must be present, and ommitted entries will use their
// IP family default for the route table.  For IPv4 for example, setting the
// gateway to 1.2.3.4 and the interface to eth0 will set up a standard
// destination of 0.0.0.0(or *) when viewed in the route table.
type Route struct {
	// Sets the destination and mask, should be a CIDR.  Accepts IPv4 and IPv6
	Destination string `json:"destination,omitempty"`

	// Sets the source and mask, should be a CIDR.  Accepts IPv4 and IPv6
	Source string `json:"source,omitempty"`

	// Sets the gateway.  Accepts IPv4 and IPv6
	Gateway string `json:"gateway,omitempty"`

	// The device to set this route up for, for example: eth0
	InterfaceName string `json:"interface_name,omitempty"`
}

// This represents a UidMapping/GidMapping for User Namespaces.
type IdMap struct {
	HostId      uint32 `json:"host_id,omitempty"`
	ContainerId uint32 `json:"container_id,omitempty"`
	Size        uint32 `json:"size,omitempty"`
}
