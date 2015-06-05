package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
)

var container libcontainer.Container

func containerPreload(context *cli.Context) error {
	c, err := getContainer(context)
	if err != nil {
		return err
	}
	container = c
	return nil
}

var factory libcontainer.Factory

func factoryPreload(context *cli.Context) error {
	f, err := loadFactory(context)
	if err != nil {
		return err
	}
	factory = f
	return nil
}

// loadConfig loads the specified config file from the path or creates
// a new config from the default template and populates it with runtime
// specific data from the cli context.
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

// loadFactory returns the configured factory instance for execing containers.
func loadFactory(context *cli.Context) (libcontainer.Factory, error) {
	root := context.GlobalString("root")
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return libcontainer.New(abs, libcontainer.Cgroupfs, func(l *libcontainer.LinuxFactory) error {
		l.CriuPath = context.GlobalString("criu")
		return nil
	})
}

// getContainer returns the specified container instance by loading it from state
// with the default factory.
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

// fatal prints the error's details if it is a libcontainer specific error type
// then exists the program with an exit status of 1.
func fatal(err error) {
	if lerr, ok := err.(libcontainer.Error); ok {
		lerr.Detail(os.Stderr)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// fatalf formats the errror string with the specified template then exits the
// program with an exit status of 1.
func fatalf(t string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, t, v...)
	os.Exit(1)
}

// getDefaultID returns a string to be used as the container id based on the
// current working directory of the nsinit process.  This function panics
// if the cwd is unable to be found based on a system error.
func getDefaultID() string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Base(cwd)
}

func getDefaultImagePath(context *cli.Context) string {
	return filepath.Join("/tmp/nsinit/checkpoints", context.String("id"))
}
