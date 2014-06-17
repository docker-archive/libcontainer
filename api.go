/*
API for libcontainer.

NOTE: The API is in flux and mainly not implemented. Proceed with caution until further notice.
*/
package libcontainer

import (
	"fmt"
	"io"

	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/cgroups/fs"
	"github.com/docker/libcontainer/network"
)

// Factory of libcontainer containers.
//
// Container names are a user-provided identifier for a container.
type Libcontainer interface {
	// Creates a new container as specified, and starts an init process inside.
	//
	// Errors: name already exists,
	//         config invalid,
	//         system error in creation.
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	StartIn(name Name, config *Config, initialProcess *ProcessConfig) (*Container, int, error)

	// Creates a new container with the specified name and config.
	//
	// The container does not have namespaces.
	//
	// Errors: name already exists,
	//         config invalid,
	//         system error in creation.
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	Create(name Name, config *Config) (*Container, error)

	// Gets an existing container with the specified name.
	//
	// Errors: name does not refer to an existing container.
	Get(name Name) (*Container, error)
}

// A libcontainer container object. Must be created by Libcontainer above.
//
// Each container is thread-safe within the same process. Since a container can
// be destroyed by a separate process, any function may return ErrNotFound.
type Container interface {
	// Returns the name of this container.
	Name() Name

	// Returns the current run state of the container.
	//
	// Errors: container no longer exists,
	//         system error retrieving the run state.
	RunState() (RunState, error)

	// Returns the current config of the container.
	//
	// Errors: container no longer exists,
	//         system error retrieving the config.
	Config() (*Config, error)

	// Updates the container's cgroups as per the config.
	//
	// If an update fails, the update may only be partially applied.
	//
	// Errors: container no longer exists,
	//         invalid config specified,
	//         system error applying the config.
	UpdateCgroups(config *cgroups.Cgroup)

	// TODO(vmarmol): Add other update types:
	// - Mounts
	// - Devices
	// - Network

	// Destroys the container after killing all running processes.
	//
	// Any event registrations are removed before the container is destroyed.
	// No error is returned if the container is already destroyed.
	//
	// Errors: system error destroying the container.
	Destroy() error

	// Runs a command inside the container. Returns the PID of the new process (in the caller process's namespace).
	//
	// Processes run inside a container with PID namespaces will be reparented to the init in that namespace.
	// Otherwise, the process will be a child of the current process and the current process must reap it by
	// calling wait() or waitpid() on it.
	//
	// If the Container state is PAUSED, the user process will immediately be paused. Execution
	// will commence only when the Container is resumed.
	//
	// Errors: container no longer exists,
	//         config is nil or invalid,
	//         the process is not executable,
	//         system error while running the process.
	RunIn(config *ProcessConfig) (int, error)

	// Returns the PIDs inside this container. The PIDs are in the namespace of the calling process.
	//
	// Errors: container no longer exists,
	//         system error fetching the list of processes.
	//
	// Some of the returned PIDs may no longer refer to processes in the Container, unless
	// the Container state is PAUSED in which case every PID in the slice is valid.
	Processes() ([]int, error)

	// Returns the TIDs inside this container. The TIDs are in the namespace of the calling process.
	//
	// Errors: container no longer exists,
	//         system error fetching the list of processes.
	//
	// Some of the returned TIDs may no longer refer to processes in the Container, unless
	// the Container state is PAUSED in which case every TID in the slice is valid.
	Threads() ([]int, error)

	// Returns complete stats for the container.
	//
	// Errors: container no longer exists,
	//         system error fetching the stats of the container.
	Stats() (*ContainerStats, error)

	// If the Container state is RUNNING or PAUSING, sets the Container state to PAUSING and pauses
	// the execution of any user processes in the Container before setting the Container state to
	// PAUSED.
	// If the Container state is PAUSED, do nothing.
	//
	// Errors: container no longer exists,
	//         system error pausing the container.
	Pause() error

	// If the Container state is PAUSED, resumes the execution of any user processes in the
	// Container before setting the Container state to RUNNING.
	// If the Container state is RUNNING, do nothing.
	//
	// Errors: container no longer exists,
	//         system error unpausing the container.
	Unpause() error

	// TODO(vmarmol,xemul): Flesh out what we need for this. These are mainly here to reserve the name.
	// Checkpoint the current state of the container.
	Checkpoint() error

	// TODO(vmarmol,xemul): Flesh out what we need for this. These are mainly here to reserve the name.
	// Restore the container from an existing checkpoint.
	Restore() error

	// Registers an interest in events of the given types. The events are delivered to the given
	// channel.
	//
	// Only events of the given types are delivered to the given channel. RegisterEvents may
	// be called more than once to register an interest in more than one set of event types
	// and/or with more than one channel. If the same channel is used multiple times, the set of
	// event types is cumulative (and so each event is sent only once to the channel).
	//
	// The order of the event types in the given slice does not affect the result: the slice is
	// treated as a set.
	//
	// If an event cannot be delivered to the channel without blocking, the event is discarded.
	// The caller should avoid losing events by providing a channel with a sufficiently large
	// buffer.
	//
	// Errors: container no longer exists,
	//         eventTypes is an empty slice,
	//         eventTypes contains an invalid EventType,
	//         system error while registering the events.
	RegisterEvents(eventTypes []EventType, eventChan <-chan Event) error

	// Removes a registration identified by the given channel. The channel is closed before
	// removal.
	//
	// Errors: container no longer exists,
	//         the channel is not registered with this container.
	RemoveEventRegistration(eChan <-chan Event) error
}

// Name of a container.
//
// Allowable characters for container names are:
// - Alpha numeric ([a-zA-Z0-9])
// - Underscores (_)
type Name string

// The running state of the container.
type RunState int

const (
	// The container exists and is running.
	RUNNING RunState = iota

	// The container exists, it is in the process of being paused.
	PAUSING RunState = iota

	// The container exists, but all its processes are paused.
	PAUSED RunState = iota
)

// EventType is used to identify a particular event.
type EventType int

const (
	// Event for changes in the container state.
	CONTAINER_STATE EventType = iota

	// Event for the out of memory (OOM) condition.
	CONTAINER_OUT_OF_MEMORY EventType = iota
)

// Base type for events.
type Event interface {
	// Returns the type of the event.
	Type() EventType
}

// Configuration for a process to be run inside a container.
type ProcessConfig struct {
	// The command to be run followed by any arguments.
	Args []string

	// Map of environment variables to their values.
	Env map[string]string

	// Stdin is a pointer to a reader which provides the standard input stream.
	// Stdout is a pointer to a writer which receives the standard output stream.
	// Stderr is a pointer to a writer which receives the standard error stream.
	//
	// If a reader or writer is nil, the input stream is assumed to be empty and the output is
	// discarded.
	//
	// The readers and writers, if supplied, are closed when the process terminates. Their Close
	// methods should be idempotent.
	//
	// Stdout and Stderr may refer to the same writer in which case the output is interspersed.
	Stdin  *io.ReadCloser
	Stdout *io.WriteCloser
	Stderr *io.WriteCloser

	// TODO(vmarmol): Complete.
	// ProcessConfig take over some of the runtime config from .
	// This is anything that can be set per-process that enters the container and its namespaces.
	//
	// Things like:
	// - Namespaces
	// - Capabilities
	// - User/Groups
	// - Working directory
}

// Error type returned when the underlying container was destroyed.
type ErrNotFound struct {
	// Name of the container that was not found.
	ContainerName Name
}

func (self ErrNotFound) Error() string {
	return fmt.Sprintf("container %q was not found, it may no longe exist", self.ContainerName)
}

// TODO(vmarmol): Move to a separate file.
// DEPRECATED: The below portions are only to be used during the transition to the above API.

// Returns all available stats for the given container.
func GetStats(container *Config, state *State) (*ContainerStats, error) {
	var containerStats ContainerStats
	stats, err := fs.GetStats(container.Cgroups)
	if err != nil {
		return &containerStats, err
	}
	containerStats.CgroupStats = stats
	networkStats, err := network.GetStats(&state.NetworkState)
	if err != nil {
		return &containerStats, err
	}
	containerStats.NetworkStats = networkStats

	return &containerStats, nil
}
