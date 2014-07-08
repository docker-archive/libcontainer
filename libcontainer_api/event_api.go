package libcontainer_api

import (
	"github.com/docker/libcontainer/cgroups"
)

// EventType is used to tag an event with its type.
type EventType int

const (
	CONTAINER_STATE         EventType = iota
	CONTAINER_OUT_OF_MEMORY EventType // see EventOOM
)

// Base type for events.
type Event interface {
	// Returns the ContainerId associated with the event.
	ContainerId() ContainerId

	// Returns the type of the event.
	Type() EventType
}

// Container state update event.
type ContainerStateEvent interface {
	// Type() == CONTAINER_STATE.
	Event

	// Returns the updated state of the Container.
	// Note: this will never be DESTROYED.
	ContainerState() ContainerState
}

// Out of memory event.
type OOMEvent interface {
	// Type() == CONTAINER_OUT_OF_MEMORY.
	Event

	// Returns memory statistics collected during OOM.
	MemoryStats() cgroups.MemoryStats
}

type EventRegistrar interface {

	// Registers an interest in events of the given types. The events are delivered to the given
	// channel. The given channel must not be closed by the caller.
	//
	// Only events of the given types are delivered to the given channel. RegisterForEvents may
	// be called more than once to register an interest in more than one set of event types
	// and/or with more than one channel. If the same channel is used multiple times, the set of
	// event types is cumulative (and so each event is sent only once to the channel).
	//
	// The order of the given event types does not affect the result: the collection is treated as
	// a set.
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
	RegisterForEvents(eventTypes []EventType, eventChan <-chan Event) error

	// Removes a registration identified by the given channel. The channel is closed before
	// removal.
	//
	// If the Container is in the DESTROYED state, do nothing.
	//
	// Errors: container no longer exists,
	//         the channel is not registered with this container.
	RemoveEventRegistration(eventChan <-chan Event) error
}
