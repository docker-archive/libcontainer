package libcontainer_api

import (
	"io"
)

// An operation on a process within a Runner.
type ProcessOp func(pid int) error

// A Runner is an execution environment in which user processes may execute (more or less)
// independently of the host system.
type Runner interface {

	// If the Container state is ACTIVE or PAUSED, creates and runs a user process inside the
	// container. Re-parents the user process to the "root" process of the Container. Returns the
	// PID of the new process (in the caller's namespace) and a readonly channel of exit statuses,
	// with a buffer size of 1.
	//
	// If the Container state is PAUSED, the user process will immediately be paused. Execution
	// will commence only when the Container is resumed.
	//
	// Errors: the Container state is neither ACTIVE nor PAUSED,
	//         processSpec is nil,
	//         the process spec is invalid,
	//         the process is not executable,
	//         system error.
	RunIn(processSpec *ProcessSpec) (pid int, exitStatus chan<- int, err error)

	// Returns the process ids of all user processes inside this Container. The process ids are in
	// the namespace of the calling process.
	//
	// Some of the returned process ids may no longer refer to processes in the Container, unless
	// the Container state is PAUSED in which case every process id in the return value is valid.
	//
	// If the Container state is STOPPED or DESTROYED, the return value will be empty.
	Processes() []int

	// TODO(vmarmol): may need Threads() if these cannot be derived from Processes().
}

// Specification for a process to be run inside a container.
type ProcessSpec struct {
	// Args consists of the command to be run followed by any arguments.
	Args []string

	// Env maps environment variable names to values.
	// TODO: document restrictions on Env map, for example the domain may not contain arbitrary strings.
	Env map[string]string

	// Stdin is a pointer to a reader which provides the standard input stream.
	// Stdout is a pointer to a writer which receives the standard output stream.
	// Stderr is a pointer to a writer which receives the standard error stream.
	//
	// If a reader or writer is nil (or has a non-nil type and nil value), the input stream is
	// assumed to be empty and the output is discarded.
	//
	// The readers and writers, if supplied, are closed when the process terminates. Their Close
	// methods should be idempotent.
	//
	// Stdout and Stderr may refer to the same writer in which case the output is interspersed.
	Stdin  io.ReadCloser
	Stdout io.WriteCloser
	Stderr io.WriteCloser

	// TODO(vmarmol): Complete.
	// Things like:
	// - Capabilities
	// - User/Groups
	// - Working directory
}
