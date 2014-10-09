package libcontainer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/Sirupsen/logrus"
	libct "github.com/avagin/libct/go"
	"github.com/docker/libcontainer/configs"
)

type libctFactory struct {
	session *libct.Session
	root    string
	systemd bool
}

func (f *libctFactory) init() error {
	initLog()
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

func (f *libctFactory) Create(id string, config *configs.Config) (Container, error) {
	if f.root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	containerRoot := filepath.Join(f.root, id)
	if _, err := os.Stat(containerRoot); err == nil {
		return nil, newGenericError(fmt.Errorf("Container with id exists: %v", id), IdInUse)
	} else if !os.IsNotExist(err) {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.MkdirAll(containerRoot, 0700); err != nil {
		return nil, newGenericError(err, SystemError)
	}

	ct, err := f.session.ContainerCreate(id)
	if err != nil {
		return nil, err
	}

	c := &libctContainer{
		id:      id,
		root:    containerRoot,
		config:  config,
		ct:      ct,
		session: f.session,
		systemd: f.systemd,
	}

	err = c.load()
	if err != nil {
		c.Destroy()
		return nil, err
	}

	return c, nil
}

func (l *libctFactory) loadState(root string) (*State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(err, ContainerNotExists)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()
	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	return state, nil
}

func (f *libctFactory) Load(id string) (Container, error) {
	if f.root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	containerRoot := filepath.Join(f.root, id)
	state, err := f.loadState(containerRoot)
	if err != nil {
		return nil, err
	}

	ct, err := f.session.ContainerCreate(id)
	if err != nil {
		return nil, err
	}
	c := &libctContainer{
		id:      id,
		root:    containerRoot,
		config:  &state.Config,
		ct:      ct,
		session: f.session,
		systemd: f.systemd,
	}

	err = c.load()
	if err != nil {
		return nil, err
	}

	pd, err := c.session.ProcessCreateDesc()
	if err != nil {
		return nil, newSystemError(err)
	}
	err = c.ct.Load(pd, state.InitProcessPid)
	if err != nil {
		return nil, err
	}

	process := &Process{}
	process.ops = &libctProcessOps{p: pd}

	c.initProcess = process

	return c, nil
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (f *libctFactory) StartInitialization() (err error) {
	return nil
}

func (l *libctFactory) Type() string {
	return "libct"
}

var libctLogInitialized bool = false

func initLog() {
	if libctLogInitialized {
		return
	}

	rlog, wlog, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	libct.LogInit(wlog, libct.LOG_INFO)
	go func() {
		sc := bufio.NewScanner(rlog)
		for sc.Scan() {
			l := sc.Text()
			if strings.HasPrefix(l, "Error") {
				log.Error(l)
			} else if strings.HasPrefix(l, "Warn") {
				log.Warn(l)
			} else {
				log.Info(l)
			}
		}
		if err := sc.Err(); err != nil {
			log.Warn(err)
		}
		rlog.Close()
	}()

	libctLogInitialized = true
}
