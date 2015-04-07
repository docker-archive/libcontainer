package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/cgroups/systemd"
	"github.com/docker/libcontainer/configs"
)

const (
	dockerRoot    = "/var/run/docker/execdriver/native"
	stateFilename = "state.json"
)

func loadDockerFactory(context *cli.Context) (libcontainer.Factory, error) {
	cgm := libcontainer.Cgroupfs
	if systemd.UseSystemd() {
		cgm = libcontainer.SystemdCgroups
	}
	return libcontainer.New(dockerRoot, cgm)
}

func loadState(root string) (*libcontainer.State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var state *libcontainer.State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, err
	}
	return state, nil
}

func loadDockerConfig(context *cli.Context) (*configs.Config, error) {
	containerRoot := filepath.Join(dockerRoot, context.String("id"))
	state, err := loadState(containerRoot)
	if err != nil {
		return nil, err
	}
	config := &state.Config
	modify(config, context)
	return config, nil
}
