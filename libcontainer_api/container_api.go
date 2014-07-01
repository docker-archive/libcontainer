package libcontainer_api

// A ContainerId uniquely identifies a Container in the host system. It is an opaque token, but
// must be comparable for equality.
type ContainerId interface{}

// Display Name of a container.
//
// Any string is permitted, used only for logging etc.
type DisplayName string

// A Container supports running user processes in a controlled environment according to the
// configuration of the Container. A Container has its own life cycle, provides statistics, and
// broadcasts events to parties who have registered an interest.
type Container interface {
	Runner
	Configurer
	StateManager
	StatsCollector
	EventRegistrar

	// Returns the ContainerId of the Container.
	ContainerId() ContainerId
}

// A Factory provides a way of creating Containers and configuration builders.
type Factory interface {

	// Creates a new Container with the given configuration and human-readable display name.
	//
	// The new Container is created with a new "root" process running inside it which will become
	// the parent of any user processes subsequently started using RunIn. The root process will
	// own any configured namespaces. Therefore, if the PID namespace is configured, the root
	// process will be the init process of the new PID namespace.
	//
	// The responsibilities of the root process include:
	//   1. Staying alive so that, if a PID namespace is configured, user processes will not be
	//      terminated prematurely and Container state is preserved.
	//   2. Reaping the exit status of user processes.
	// The root process will belong to the root of the control group hierarchy and is not subject
	// to the Container's subsystem limits.
	//
	// The display name is used in logging etc., but has no semantic significance to libcontainer.
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	//
	// Errors: config invalid,
	//         insufficient resources,
	//         system error.
	CreateContainer(config Config, displayName DisplayName) (container Container, err error)

	// Creates a new, empty configuration which may be used to create a Container.
	CreateConfig() Config
}
