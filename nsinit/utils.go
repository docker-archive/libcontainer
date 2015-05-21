package main

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"os"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/cgroups/systemd"
	"github.com/docker/libcontainer/configs"
)

func loadConfig(context *cli.Context) (*configs.Config, error) {
	if path := context.String("config"); path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var config *configs.Config
		if err := json.NewDecoder(f).Decode(&config); err != nil {
			return nil, err
		}
		return config, nil
	}
	config := getTemplate()
	modify(config, context)
	return config, nil
}

func loadFactory(context *cli.Context) (libcontainer.Factory, error) {
	factory := context.GlobalString("factory")

	if factory == "libct" {
		return libcontainer.NewLibctFactory(context.GlobalString("root"), context.Bool("systemd"))
	}
	if factory == "linux" {
		cgm := libcontainer.Cgroupfs
		if context.Bool("systemd") {
			if systemd.UseSystemd() {
				cgm = libcontainer.SystemdCgroups
			} else {
				logrus.Warn("systemd cgroup flag passed, but systemd support for managing cgroups is not available.")
			}
		}
		return libcontainer.New(context.GlobalString("root"), cgm)
	}

	return nil, fmt.Errorf("Unknown factory: %s", factory)
}

func getContainer(context *cli.Context) (libcontainer.Container, error) {
	factory, err := loadFactory(context)
	if err != nil {
		return nil, err
	}
	container, err := factory.Load(context.String("id"))
	if err != nil {
		return nil, err
	}
	return container, nil
}

func fatal(err error) {
	if lerr, ok := err.(libcontainer.Error); ok {
		lerr.Detail(os.Stderr)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func fatalf(t string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, t, v...)
	os.Exit(1)
}
