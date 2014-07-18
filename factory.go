package libcontainer

type Factory interface {
	// Creates a new container in the given path. A unique ID is generated for the container and
	// starts the initial process inside the container.
	//
	// Returns the new container with a running process.
	//
	// Errors:
	// path already exists
	// config or initialConfig is invalid
	// system error
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	Create(config *Config, initProcess *Process) (Container, error)

	// Load takes the path for an existing container and reconstructs the container
	// from the state.
	//
	// Errors:
	// path does not exist
	// container is stopped
	// system error
	Load(path string) (Container, error)

	// StartInitialization is an internal API to libcontainer used during the rexec of the
	// container.  pipefd is the fd to the child end of the pipe used to syncronize the
	// parent and child process providing state and configuration to the child process and
	// returning any errors during the init of the container
	//
	// Errors:
	// pipe connection error
	// system error
	StartInitialization(pipefd uintptr) error
}
