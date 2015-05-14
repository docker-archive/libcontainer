package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/utils"
)

var execCommand = cli.Command{
	Name:   "exec",
	Usage:  "execute a new command inside a container",
	Action: execAction,
	Flags: append([]cli.Flag{
		idFlag,
		cli.BoolFlag{Name: "tty,t", Usage: "allocate a TTY to the container"},
		cli.BoolFlag{Name: "systemd", Usage: "Use systemd for managing cgroups, if available"},
		cli.StringFlag{Name: "config", Value: "", Usage: "path to the configuration file"},
		cli.StringFlag{Name: "user,u", Value: "root", Usage: "set the user, uid, and/or gid for the process"},
		cli.StringFlag{Name: "cwd", Value: "", Usage: "set the current working dir"},
		cli.StringSliceFlag{Name: "env", Value: &cli.StringSlice{}, Usage: "set environment variables for the process"},
	}, createFlags...),
}

func execAction(context *cli.Context) {
	factory, err := loadFactory(context)
	if err != nil {
		fatal(err)
	}
	config, err := loadConfig(context)
	if err != nil {
		fatal(err)
	}
	created := false
	container, err := factory.Load(context.String("id"))
	if err != nil {
		created = true
		if container, err = factory.Create(context.String("id"), config); err != nil {
			fatal(err)
		}
	}
	process := &libcontainer.Process{
		Args:   context.Args(),
		Env:    append(os.Environ(), context.StringSlice("env")...),
		User:   context.String("user"),
		Cwd:    context.String("cwd"),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	rootuid, err := config.HostUID()
	if err != nil {
		fatal(err)
	}
	tty, err := newTty(context, process, rootuid)
	if err != nil {
		fatal(err)
	}
	go handleSignals(process, tty)
	if err := container.Start(process); err != nil {
		tty.Close()
		if created {
			container.Destroy()
		}
		fatal(err)
	}
	status, err := process.Wait()
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if ok {
			status = exitError.ProcessState
		} else {
			tty.Close()
			if created {
				container.Destroy()
			}
			fatal(err)
		}
	}
	if created {
		status, err := container.Status()
		if err != nil {
			tty.Close()
			fatal(err)
		}
		if status != libcontainer.Checkpointed {
			if err := container.Destroy(); err != nil {
				tty.Close()
				fatal(err)
			}
		}
	}
	tty.Close()
	os.Exit(utils.ExitStatus(status.Sys().(syscall.WaitStatus)))
}

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
