package libcontainer

import (
	"encoding/json"
	"os"
	"runtime"

	"github.com/docker/libcontainer/label"
	"github.com/docker/libcontainer/network"
	"github.com/docker/libcontainer/syncpipe"
)

type linuxFactory struct {
	initArgs []string
}

// New returns the default factory for container creation in libcontainer
func New(initArgs []string) Factory {
	return &linuxFactory{
		initArgs: initArgs,
	}
}

func (f *linuxFactory) Create(config *Config, initProcess *Process) (Container, error) {
	state := &State{
		Status:       Created,
		NetworkState: network.NetworkState{},
	}

	container := newLinuxContainer(config, state)

	pipe, err := syncpipe.NewSyncPipe()
	if err != nil {
		return nil, err
	}

	if err := initProcess.createCommand(f.initArgs, config, pipe); err != nil {
		return nil, err
	}

	if err := container.startInitProcess(initProcess); err != nil {
		return nil, err
	}

	return container, nil
}

func (f *linuxFactory) Load(path string) (Container, error) {
	panic("not implemented")
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (f *linuxFactory) StartInitialization(pipefd uintptr) (err error) {
	f.initialGlobalState()

	// clear the current processes environment and load in the containers
	os.Clearenv()

	pipe, err := syncpipe.NewSyncPipeFromFd(0, pipefd)
	if err != nil {
		return err
	}

	defer func() {
		// if we have an error ensure that our parent process is notified
		if err != nil {
			pipe.ReportChildError(err)
		}
	}()

	rawState, err := pipe.ReadFromParent()
	if err != nil {
		return err
	}

	var state *initState
	if err := json.Unmarshal(rawState, &state); err != nil {
		return err
	}

	// update the status to reflect that we are currently running in the init process
	state.State.Status = Init

	// now that we have the initState we can reconstruct the container
	container := newLinuxContainer(state.Config, state.State)

	return container.initializeNamespace(state.Process)
}

func (f *linuxFactory) initialGlobalState() {
	runtime.LockOSThread()
	label.Init()
}

type initState struct {
	Process *Process `json:"process,omitempty"`
	Config  *Config        `json:"config,omitempty"`
	State   *State         `json:"state,omitempty"`
}
