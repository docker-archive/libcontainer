package libcontainer

import "github.com/docker/libcontainer/network"

// State represents a running container's state
type State struct {
	// InitPid is the init process id in the parent namespace
	InitPid int `json:"init_pid,omitempty"`

	// InitStartTime is the init process start time
	InitStartTime string `json:"init_start_time,omitempty"`

	// Network runtime state.
	NetworkState network.NetworkState `json:"network_state,omitempty"`

	// Status of the container
	Status Status `json:"status,omitempty"`
}

// Status of the container
type Status int

func (s Status) String() string {
	switch s {
	case Created:
		return "created"
	case Running:
		return "running"
	case Pausing:
		return "pausing"
	case Paused:
		return "paused"
	case Destroyed:
		return "destroyed"
	case Init:
		return "init"
	}

	return "unknown"
}

const (
	// The name of the runtime state file
	stateFile = "state.json"

	// The container has been created but no processes are running.
	Created Status = iota

	// The container exists and is running.
	Running

	// The container exists, it is in the process of being paused.
	Pausing

	// The container exists, but all its processes are paused.
	Paused

	// The container does not exist.
	Destroyed

	// The container is in the init state inside a newly created namespace
	Init
)
