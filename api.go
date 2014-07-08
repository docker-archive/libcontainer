/*
API for libcontainer.

NOTE: The API is in flux and mainly not implemented. Proceed with caution until further notice.
*/
package libcontainer

import (
	"io"

	"github.com/docker/libcontainer/cgroups"
)

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

	// The container does not exist.
	DESTROYED RunState = iota
)

// Configuration for a process to be run inside a container.
type ProcessConfig struct {
	// The command to be run followed by any arguments.
	Args []string

	// Map of environment variables to their values.
	Env []string

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
	// ProcessConfig take over some of the runtime config from Config.
	// This is anything that can be set per-process that enters the container and its namespaces.
	//
	// Things like:
	// - Namespaces
	// - Capabilities
	// - User/Groups
	// - Working directory
}

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

// Container run state update event.
type RunStateEvent interface {
	// Type() == CONTAINER_STATE.
	Event

	// Returns the updated run state of the Container.
	// Note: this will never be DESTROYED.
	RunState() RunState
}

// Out of memory event.
type OOMEvent interface {
	// Type() == CONTAINER_OUT_OF_MEMORY.
	Event

	// Returns memory statistics collected during OOM.
	MemoryStats() cgroups.MemoryStats
}

// Factory of libcontainer containers.
type Factory interface {
	// Creates a new container as specified, and starts an init process inside.
	//
	// The container and PID of the init process is returned. The init must be reaped by the caller.
	//
	// Errors: name already exists,
	//         config or initialConfig invalid,
	//         system error.
	//
	// Arguments:
	//   name: The user-provided name of the container. Used to identify this container, must be unique
	//         in this machine.
	//   config: The configuration of the new container.
	//   initialProcess: The configuration of the init to run inside the container.
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	Create(name Name, config *Config, initialProcess *ProcessConfig) (*Container, int, error)
}

// A libcontainer container object. Must be created by the Factory above.
//
// Each container is thread-safe within the same process. Since a container can
// be destroyed by a separate process, any function may return that the container
// was not found.
type Container interface {
	// Returns the name of this container.
	Name() Name

	// Returns the current run state of the container.
	//
	// Errors: container no longer exists,
	//         system error.
	RunState() (RunState, error)

	// Returns the current config of the container.
	//
	// Errors: container no longer exists,
	//         system error.
	Config() (*Config, error)

	// Destroys the container after killing all running processes.
	//
	// Any event registrations are removed before the container is destroyed.
	// No error is returned if the container is already destroyed.
	//
	// Errors: system error.
	Destroy() error

	// Returns the PIDs inside this container. The PIDs are in the namespace of the calling process.
	//
	// Errors: container no longer exists,
	//         system error.
	//
	// Some of the returned PIDs may no longer refer to processes in the Container, unless
	// the Container state is PAUSED in which case every PID in the slice is valid.
	Processes() ([]int, error)

	// Returns statistics for the container.
	//
	// Errors: container no longer exists,
	//         system error.
	Stats() (*ContainerStats, error)

	// If the Container state is RUNNING or PAUSING, sets the Container state to PAUSING and pauses
	// the execution of any user processes. Asynchronously, when the container finished being paused the
	// state is changed to PAUSED.
	// If the Container state is PAUSED, do nothing.
	//
	// Errors: container no longer exists,
	//         system error.
	Pause() error

	// If the Container state is PAUSED, resumes the execution of any user processes in the
	// Container before setting the Container state to RUNNING.
	// If the Container state is RUNNING, do nothing.
	//
	// Errors: container no longer exists,
	//         system error.
	Resume() error

	// Registers an interest in events of the given types. The events are delivered to the given
	// channel. The given channel must not be closed by the caller.
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
	// If the Container is in the DESTROYED state, do nothing.
	//
	// The registration may be removed using RemoveEventRegistration. If a Container is
	// destroyed, any event registrations are automatically removed and the corresponding channels
	// closed before the Container state transitions to DESTROYED.
	//
	// A single event channel should not be registered with multiple Containers as it will be
	// closed when it is unregistered from one of the Containers or when one of the Containers
	// is destroyed.
	//
	// Errors: container no longer exists,
	//         eventTypes is an empty slice,
	//         eventTypes contains an invalid EventType,
	//         system error.
	RegisterEvents(eventTypes []EventType, eventChan <-chan Event) error

	// Removes a registration identified by the given channel. The channel is closed before
	// removal.
	//
	// If the Container is in the DESTROYED state, do nothing.
	//
	// Errors: container no longer exists,
	//         the channel is not registered with this container.
	RemoveEventRegistration(eChan <-chan Event) error
}
