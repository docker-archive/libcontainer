package libcontainer

import (
	"encoding/json"
	"log"
	"os"
	"runtime"

	"github.com/docker/libcontainer/label"
	"github.com/docker/libcontainer/network"
	"github.com/docker/libcontainer/syncpipe"
)

type linuxFactory struct {
	initArgs []string
	logger   *log.Logger
}

// New returns the default factory for container creation in libcontainer
// initArgs are the arguments passed during the reexec of the process with
// the binary of the app to execute
func New(initArgs []string, logger *log.Logger) Factory {
	return &linuxFactory{
		initArgs: initArgs,
		logger:   logger,
	}
}

func (f *linuxFactory) Create(config *Config, initProcess *Process) (Container, error) {
	state := &State{
		Status:       Created,
		NetworkState: network.NetworkState{},
	}

	f.logger.Println("begin container creation")

	container := newLinuxContainer(config, state, f.logger)

	pipe, err := syncpipe.NewSyncPipe()
	if err != nil {
		return nil, err
	}
	f.logger.Printf("create syncpipe with parent: %d child: %d\n", pipe.Parent().Fd(), pipe.Child().Fd())

	if err := initProcess.createCommand(f.initArgs, config, pipe); err != nil {
		return nil, err
	}

	f.logger.Println("starting init process")

	if err := container.startInitProcess(initProcess); err != nil {
		return nil, err
	}

	f.logger.Println("init process started")

	return container, nil
}

func (f *linuxFactory) Load(path string) (Container, error) {
	panic("not implemented")
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (f *linuxFactory) StartInitialization(pipefd uintptr) (err error) {
	f.logger.Println("locking os thread and initializing label system")

	runtime.LockOSThread()
	label.Init()

	// clear the current processes environment and load in the containers
	os.Clearenv()

	f.logger.Printf("connecting to syncpipe via fd: %d\n", pipefd)

	pipe, err := syncpipe.NewSyncPipeFromFd(0, pipefd)
	if err != nil {
		return err
	}

	defer func() {
		// if we have an error ensure that our parent process is notified
		if err != nil {
			f.logger.Printf("sending error %q to parent process\n", err)

			pipe.ReportChildError(err)
		}
	}()

	f.logger.Println("reading init state from parent")

	rawState, err := pipe.ReadFromParent()
	if err != nil {
		return err
	}

	f.logger.Println("received init state from parent")

	var state *initState
	if err := json.Unmarshal(rawState, &state); err != nil {
		return err
	}

	// update the status to reflect that we are currently running in the init process
	state.State.Status = Init

	// now that we have the initState we can reconstruct the container
	container := newLinuxContainer(state.Config, state.State, f.logger)

	return container.initializeNamespace(state.Process)
}
