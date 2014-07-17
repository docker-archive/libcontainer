package libcontainer

import "github.com/docker/libcontainer/syncpipe"

type linuxFactory struct {
}

// New returns the default factory for container creation in libcontainer
func New() Factory {
	return &linuxFactory{}
}

// tty
// veths
func (f *linuxFactory) Create(path string, config *Config, initProcess *ProcessConfig) (Container, error) {
	state := &State{
		Status:       Created,
		NetworkState: Network{},
	}

	container := newLinuxContainer(path, config, state)

	pipe, err := syncpipe.NewSyncPipe()
	if err != nil {
		return nil, err
	}

	if config.Tty {
		if err := initProcess.allocatePty(); err != nil {
			return nil, err
		}
	}

	if err := initProcess.createCommand(path, config, pipe); err != nil {
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
