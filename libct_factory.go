package libcontainer

import (
	"log"

	libct "github.com/xemul/libct/go"
	"github.com/docker/libcontainer/network"
	"github.com/docker/libcontainer/syncpipe"
)

type libctFactory struct {
	initArgs []string
	logger   *log.Logger
	session  *libct.Session
}

func (f *libctFactory) init() error {
	if f.session != nil {
		return nil
	}

	s := &libct.Session{}
	err := s.OpenLocal()
	if err != nil {
		return err
	}

	f.session = s
	return nil
}

func (f *libctFactory) Create(config *Config, initProcess *Process) (Container, error) {
	if err := f.init(); err != nil {
		return nil, err
	}

	state := &State{
		Status:       Created,
		NetworkState: network.NetworkState{},
	}

	f.logger.Println("begin container creation")

	ct, err := f.session.ContainerCreate("docker")
	if err != nil {
		return nil, err
	}

	container := newLibctContainer(config, state, f.logger, ct)

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

func (f *libctFactory) Load(path string) (Container, error) {
	panic("not implemented")
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (f *libctFactory) StartInitialization(pipefd uintptr) (err error) {
	return nil
}
