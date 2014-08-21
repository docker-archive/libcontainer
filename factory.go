package libcontainer

// A Factory generates new (or recovers old) Containers.
type Factory interface {
	// Creates a new container with the given configuration.
	// Returns the new container.
	//
	// The new Container value controls the system container.
	//
	// Errors:
	// Config is invalid
	// System error
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	Create(config *Config) (Container, error)

	// Recreates a Container value from the given Memento (which was previously passed to a Memo function).
	// Returns the recreated Container.
	//
	// The nil Memento is invalid.
	//
	// If no Container value is in control, the recreated Container value now controls the system container.
	//
	// Import has two intended uses. It may be used to recover a Container if the original value is lost, for example if
	// the creating process terminates. In this case, the recovered Container is fully functional except that it has no
	// Memo functions registered.
	//
	// Import may also be used to access an existing system container. In this case, the recovered Container value should
	// is not in control and should only be used to read information, for example to gather statistics. There is no point
	// in registering a Memo function with this Container.
	//
	// Errors:
	// Container no longer exists
	// Invalid memento
	// System error
	Import(memento Memento) (Container, error)
}
