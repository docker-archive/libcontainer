/*
NOTE: The API is in flux and mainly not implemented. Proceed with caution until further notice.
*/
package libcontainer

// A libcontainer container object.
//
// Each container is thread-safe within the same process. Since a container can
// be destroyed by a separate process, any function may return that the container
// was not found.
type Container interface {
	// Path returns the path to the container's directory containing the state
	Path() string

	// Returns the current status of the container.
	Status() Status

	// Returns the current config of the container.
	Config() *Config

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
}
