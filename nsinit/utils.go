package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
)

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

// handleSignals forwards signals from the current process to the container
// while still allowing any configured TTY to have SIGWINCH signals interpreted
// as resize events.
func handleSignals(container *libcontainer.Process, tty *tty) {
	sigc := make(chan os.Signal, 10)
	signal.Notify(sigc)
	tty.resize()
	for sig := range sigc {
		switch sig {
		case syscall.SIGWINCH:
			tty.resize()
		default:
			container.Signal(sig)
		}
	}
}
