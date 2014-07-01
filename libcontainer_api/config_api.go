package libcontainer_api

import (
	"github.com/docker/libcontainer/devices"
)

type Configurer interface {

	// Returns the display name of the Container, even if it has been destroyed.
	DisplayName() DisplayName

	// Returns a copy of the current configuration of the Container.
	// No state changes.
	//
	// Errors: container no longer exists,
	//         system error retrieving the config.
	Config() (Config, error)

	// Modifies the current configuration of the Container.
	//
	// Errors: container no longer exists,
	//         config invalid,
	//         insufficient resources,
	//         system error.
	UpdateConfig(config Config) error
}

// Config describes a Container's configuration.
type Config interface {
	CgroupSubsystemSettings
	// TODO: other settings (network, mounts, devices, etc.)
}

// Settings of Cgroup subsystems.
type CgroupSubsystemSettings interface {
	AllowedDevices() SetterDevices // Unset means all devices are allowed. An empty slice means no devices are allowed.

	MemoryLimit() SetterInt64
	MemoryReservation() SetterInt64
	MemorySwap() SetterInt64

	CpuShares() SetterInt64
	CpuQuota() SetterInt64
	CpuPeriod() SetterInt64
	CpusetCpus() SetterString
}

// Go does not support generics ;-)

type SetterInt64 interface {
	Set(value int64)
	Unset()
	Value() (isSet bool, value int64)
}

type SetterString interface {
	Set(value string)
	Unset()
	Value() (isSet bool, value string)
}

type SetterDevices interface {
	Set(value []devices.Device)
	Unset()
	Value() (isSet bool, value []devices.Device)
}
