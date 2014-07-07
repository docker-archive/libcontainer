/*
API for libcontainer.

NOTE: The API is in flux and mainly not implemented. Proceed with caution until further notice.
*/
package libcontainer

import (
	"io"

	"github.com/docker/libcontainer/cgroups"
)

// Factory of containers.
type Factory interface {
	// Creates a new container as configured, starts an initial process inside, and returns
	// the container, the process id of the initial process in the caller's namespace, and a readonly channel of
	// exit statuses, with a buffer size of 1.
	//
	// TODO: describe what namespaces must be configured.
	// TODO: is the initial process responsible for reaping children created using RunIn?
	// TODO: is the container destroyed when the initial process terminates?
	//
	// Errors: config invalid,
	//         system error in creation.
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	StartIn(name DisplayName, config *Config, processConfig *ProcessConfig) (container Container, pid int, exitStatus chan<- int, err error)

	// Creates a new container as configured, and returns the container.
	//
	// The container does not have namespaces.
	// TODO: describe what namespaces must not be configured.
	//
	// Errors: config invalid,
	//         system error in creation.
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	Create(name DisplayName, config *Config) (container Container, err error)
}

// A container object.
type Container interface {
	// Returns the display name of this container, even if it has been destroyed.
	DisplayName() DisplayName

	// Returns the current state of this container, including DESTROYED if the container no longer exists.
	RunState() RunState

	// Returns the current config of the container.
	//
	// Errors: container no longer exists,
	//         system error retrieving the config.
	Config() (*Config, error)

	// Updates the container's cgroups as per the config.
	//
	// If a system error is returned, the update may only be partially applied.
	//
	// Errors: container no longer exists,
	//         config invalid,
	//         system error applying the config.
	UpdateCgroups(config *cgroups.Cgroup) error

	// TODO(vmarmol): Add other update types:
	// - Mounts
	// - Devices
	// - Network

	// Destroys the container after killing all running processes.
	//
	// Any event registrations are removed before the container is destroyed.
	// If the container is already destroyed, does nothing.
	//
	// Errors: system error destroying the container.
	Destroy() error

	// Runs a command inside the container and returns the process id of the new process (in the caller's namespace).
	//
	// Processes run inside a container with PID namespaces will be reparented to the initial process of that namespace.
	// TODO: In this case, how is the exit status supposed to be obtained? See StartIn.
	// Otherwise, the process will be a child of the current process and the current process must reap it by
	// calling wait() or waitpid() on it.
	//
	// If the Container state is PAUSED, the user process will immediately be paused. Execution
	// will commence only when the Container is resumed.
	//
	// Errors: container no longer exists,
	//         config invalid,
	//         the process is not executable,
	//         system error while starting the process.
	RunIn(processConfig *ProcessConfig) (pid int, err error)

	// Returns the PIDs inside this container. The PIDs are in the caller's namespace.
	// TODO: define "inside". Especially in the case of a container without namespaces.
	//
	// Errors: container no longer exists,
	//         system error fetching the list of processes.
	//
	// Some of the returned PIDs may no longer refer to processes in the Container, unless
	// the Container state is PAUSED in which case every PID in the slice is valid.
	Processes() ([]int, error)

	// Returns the TIDs inside this container. The TIDs are in the caller's namespace.
	// TODO: define "inside". Especially in the case of a container without namespaces.
	//
	// Errors: container no longer exists,
	//         system error fetching the list of processes.
	//
	// Some of the returned TIDs may no longer refer to processes in the Container, unless
	// the Container state is PAUSED in which case every TID in the slice is valid.
	Threads() ([]int, error)

	// Returns statistics for the container.
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
	//         system error resuming the container.
	Resume() error

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
	RemoveEventRegistration(eventChan <-chan Event) error
}

// Display Name of a container.
//
// Any string is permitted, used only for logging etc.
type DisplayName string

// The running state of the container.
type RunState int

const (
	// The container exists and is running.
	RUNNING RunState = iota

	// The container exists, it is in the process of being paused.
	PAUSING RunState = iota

	// The container exists, but all its processes are paused.
	PAUSED RunState = iota

	// The container has been destroyed.
	DESTROYED RunState = iota
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

// Container state update event.
type ContainerStateEvent interface {
	// Type() == CONTAINER_STATE
	Event

	// Returns updated state of the container.
	// Note: this will never be DESTROYED.
	ContainerState() RunState
}

// Out of memory event.
type OOMEvent interface {
	// Type() == CONTAINER_OUT_OF_MEMORY
	Event

	// Returns memory statistics collected during OOM.
	MemoryStats() cgroups.MemoryStats
}

// Configuration for a process to be run inside a container.
type ProcessConfig struct {
	// The command to be run followed by any arguments.
	Args []string

	// Map of environment variables to their values.
	// TODO: Are some names, such as "PWD", invalid?
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
