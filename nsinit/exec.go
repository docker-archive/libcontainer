package main

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/utils"
)

var execCommand = cli.Command{
	Name:  "exec",
	Usage: "execute a new command inside the container",
	Flags: append([]cli.Flag{
		idFlag,
		cli.BoolFlag{Name: "tty,t", Usage: "allocate a TTY to the container"},
		cli.StringFlag{Name: "config", Value: "", Usage: "path to the configuration file"},
		cli.StringFlag{Name: "user,u", Value: "root", Usage: "set the user, uid, and/or gid for the process"},
		cli.StringFlag{Name: "cwd", Value: "", Usage: "set the current working dir"},
	}, createFlags...),
	Action: func(context *cli.Context) {
		config, err := loadConfig(context)
		if err != nil {
			fatal(err)
		}
		status, err := execContainer(context, config)
		if err != nil {
			fatal(err)
		}
		os.Exit(status)
	},
}

func execContainer(context *cli.Context, config *configs.Config) (int, error) {
	rootuid, err := config.HostUID()
	if err != nil {
		return -1, err
	}
	factory, err := loadFactory(context)
	if err != nil {
		return -1, err
	}
	created := false
	container, err := factory.Load(context.String("id"))
	if err != nil {
		created = true
		if container, err = factory.Create(context.String("id"), config); err != nil {
			return -1, err
		}
	}
	// ensure that the container is always removed if we were the process
	// that created it.
	defer func() {
		if created {
			if err := container.Destroy(); err != nil {
				logrus.Error(err)
			}
		}
	}()
	process := newProcess(context)
	tty, err := newTty(context, process, rootuid)
	if err != nil {
		return -1, err
	}
	defer tty.Close()
	go handleSignals(process, tty)
	return runProcess(container, process)
}

func runProcess(container libcontainer.Container, process *libcontainer.Process) (int, error) {
	if err := container.Start(process); err != nil {
		return -1, err
	}
	status, err := process.Wait()
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			return -1, err
		}
		status = exitError.ProcessState
	}
	return utils.ExitStatus(status.Sys().(syscall.WaitStatus)), nil
}

func newProcess(context *cli.Context) *libcontainer.Process {
	return &libcontainer.Process{
		Args:   context.Args(),
		Env:    os.Environ(),
		User:   context.String("user"),
		Cwd:    context.String("cwd"),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

}
