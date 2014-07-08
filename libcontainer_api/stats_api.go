package libcontainer_api

import (
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/network"
)

// Statistics about a Container.
type ContainerStats interface {

	// Returns the cgroup stats.
	CgroupStats() *cgroups.Stats // TODO: consider returning an interface.

	// Returns the network stats.
	NetworkStats() *network.NetworkStats // TODO: consider returning an interface.

	// TODO: add other stats
}

type StatsCollector interface {

	// Returns statistics for the Container.
	//
	// If the Container is in the DESTROYED state, do nothing.
	//
	// Errors: container no longer exists,
	//         system error.
	CollectStats() (stats ContainerStats, err error)
}
