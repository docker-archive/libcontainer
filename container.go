/*
NOTE: The API is in flux and mainly not implemented. Proceed with caution until further notice.
*/
package libcontainer

// A Memento contains private state. A Memento and associated system resources are sufficient to reconstruct a Container
// value.
type Memento []byte

// A Memo function receives Mementos.
//
// The container identifier (see Id()) and the Memento are passed as parameters. If the Memento is nil, this indicates
// the container has been destroyed. If the Memento is non-nil, it represents the state of the container.
//
// The return boolean determines whether the Memo function will be called again. The function
// may be called again if it returns true but will not be called again if it returns false.
//
// A Memo function must not call the libcontainer API otherwise the behaviour is undefined.
type Memo func(id string, memento Memento) bool

// A Container value accesses, and may control, a system container, implemented with system resources.
//
// Containers are created using the Factory interface.
//
// The Container value and the system container between them constitute the entire state of the container. Multiple
// Container values can refer to the same system container but at most one may control the system container. The Factory
// interface describes which Container value controls the system container.
//
// The Container value that controls a system container is allowed to update it. Updates from other Container values
// are undefined.
//
// After Destroy() all methods (except Id()) will return 'container no longer exists'.
type Container interface {
	// Returns a system-wide, unique, automatically generated identifier for this container.
	Id() string

	// Returns the current run state of the container.
	//
	// Errors:
	// Container no longer exists
	// System error
	RunState() (*RunState, error)

	// Returns the current config of the container.
	Config() *Config

	// Registers a Memo function with this Container. libcontainer calls the Memo to provide Mementos which can be used
	// to re-create the Container (see Factory.Import).
	//
	// Calls the given Memo synchronously before RegisterMemo returns and, asynchronously after RegisterMemo returns,
	// each time the Memento changes or the container is destroyed.
	//
	// Multiple Memo functions may be registered with a given Container. A single Memo function may be registered with
	// multiple Containers.
	//
	// Errors:
	// Container no longer exists
	// System error
	// TODO: replace this with a "memo" event type when events are introduced.
	RegisterMemo(memo Memo) error

	// Start a process inside the container. Returns the PID of the new process (in the caller process's namespace) and
	// a channel that will return the exit status of the process whenever it dies.
	//
	// Errors:
	// Container no longer exists
	// Config is invalid
	// Container is paused
	// System error
	Start(*ProcessConfig) (pid int, exitChan chan int, err error)

	// Destroys the container after killing all running processes.
	//
	// Any registered Memos are notified with a nil Memento and are not subsequently called for this container.
	// No action is taken if the container is already destroyed.
	//
	// Errors:
	// System error
	Destroy() error

	// Returns the PIDs inside this container. The PIDs are in the namespace of the calling process.
	//
	// Errors:
	// Container no longer exists
	// System error
	//
	// Some of the returned PIDs may no longer refer to processes in the Container, unless
	// the Container state is PAUSED in which case every PID in the slice is valid.
	Processes() ([]int, error)

	// Returns statistics for the container.
	//
	// Errors:
	// Container no longer exists
	// System error
	Stats() (*ContainerStats, error)

	// If the Container state is RUNNING or PAUSING, sets the Container state to PAUSING and pauses
	// the execution of any user processes. Asynchronously, when the container finished being paused the
	// state is changed to PAUSED.
	// If the Container state is PAUSED, do nothing.
	//
	// Errors:
	// Container no longer exists
	// System error
	Pause() error

	// If the Container state is PAUSED, resumes the execution of any user processes in the
	// Container before setting the Container state to RUNNING.
	// If the Container state is RUNNING, do nothing.
	//
	// Errors:
	// Container no longer exists
	// System error
	Resume() error
}
