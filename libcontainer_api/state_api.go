package libcontainer_api

// ContainerState models a Container's state.
//
// A Container has a life cycle. It is ACTIVE when created and may be paused, continued, stopped,
// started and destroyed.
//
// A state transition diagram is shown below. Only the valid transitions that change the state are
// shown. The initial state is ACTIVE, and the Container may be destroyed only in the STOPPED
// state (unless the Destroy is forced — not shown).
//
// Internal state transitions from the PAUSING and STOPPING states are labelled (tau). This means
// that the transition occurs asynchronously. The transition may be detected by examining the
// state or listening to events. PAUSING and STOPPING are required so as to avoid having to
// synchronise certain other Container API operations during a Pause or Stop, which may take some
// time or may fail.
//
// ┌─────>ACTIVE───────────────>PAUSING<───┐
// │   Stop│ ^  Pause         Stop│ │(tau) │
// │       │ │         ┌──────────┘ │      │
// │       │ │         │            │      │
// │       │ └─────────│──────────┐ │      │
// │       │           │          │ │      │
// │       │ ┌─────────┘          │ │      │
// │       │ │                    │ │      │
// │       v v            Continue│ v      │
// │    STOPPING<───────────────PAUSED     │
// │        │(tau)          Stop           │
// │        │                              │
// │Start   v   Pause                      │
// └─────STOPPED───────────────────────────┘
//          │Destroy
//          │
//          v
//      DESTROYED
type ContainerState int

const (
	ACTIVE    ContainerState = iota
	PAUSING   ContainerState
	PAUSED    ContainerState
	STOPPING  ContainerState
	STOPPED   ContainerState
	DESTROYED ContainerState
)

// A StateManager provides access to a Container's state and allows the state to be changed.
type StateManager interface {

	// Returns the current state of the Container.
	State() ContainerState

	// If the Container state is ACTIVE or PAUSING, sets the Container state to PAUSING and pauses
	// the execution of any user processes in the Container before setting the Container state to
	// PAUSED.
	// If the Container state is PAUSED, do nothing.
	// If the Container state is anything else, return an error.
	//
	// Errors: the Container state was not ACTIVE, PAUSING or PAUSED,
	//         system error.
	Pause() error

	// If the Container state is PAUSED, allows the execution of any user processes in the
	// Container to continue before setting the Container state to ACTIVE.
	// If the Container state is ACTIVE, do nothing.
	// If the Container state is anything else, return an error.
	//
	// Errors: the Container state was not PAUSED or ACTIVE,
	//         system error.
	Continue() error

	// If the Container state is STOPPED or DESTROYED, does nothing.
	// If the Container state is anything else, sets the Container state to STOPPING and
	// terminates all the user processes in the Container before setting the Container state to
	// STOPPED.
	//
	// If force is false, terminates user processes by sending SIGTERM. If some user processes
	// do not terminate in time, leaves the Container in STOPPING state and returns an error.
	// Re-issuing Stop will retry. If all user processes terminate, leaves the Container in
	// STOPPED state.
	//
	// If force is true, terminates user processes by sending SIGKILL and leaves the Container in
	// STOPPED state.
	//
	// Errors: some user processes could not be killed,
	//         system error.
	Stop(force bool) error

	// If the Container state is STOPPED, set the state to ACTIVE; there are no other changes.
	// If the Container state is ACTIVE, do nothing.
	// If the Container state is anything else, return an error.
	//
	// Errors: the Container state was not STOPPED or ACTIVE,
	//         system error.
	Start() error

	// Destroys the Container and removes the associated state.
	//
	// If the Container is already in the DESTROYED state, does nothing.
	//
	// If force is false, the Container must in the STOPPED state.
	// If force is true, the Container will be force stopped before it is destroyed.
	//
	// Any event registrations are removed before the Container is destroyed (but after it is
	// stopped, if force is true).
	//
	// Errors: force is false and the Container is not in the STOPPED state,
	//         force is true and the Container cannot be stopped,
	//         system error.
	Destroy(force bool) error
}
