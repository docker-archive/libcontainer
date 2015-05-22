package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/utils"
)

var restoreCommand = cli.Command{
	Name:  "restore",
	Usage: "restore a container from a previous checkpoint",
	Flags: []cli.Flag{
		idFlag,
		cli.StringFlag{Name: "image-path", Value: "", Usage: "path to criu image files for restoring"},
		cli.StringFlag{Name: "work-path", Value: "", Usage: "path for saving work files and logs"},
		cli.BoolFlag{Name: "tcp-established", Usage: "allow open tcp connections"},
		cli.BoolFlag{Name: "ext-unix-sk", Usage: "allow external unix sockets"},
		cli.BoolFlag{Name: "shell-job", Usage: "allow shell jobs"},
	},
	Action: func(context *cli.Context) {
		imagePath := context.String("image-path")
		if imagePath == "" {
			imagePath = getDefaultImagePath(context)
		}
		config, err := loadConfig(context)
		if err != nil {
			fatal(err)
		}
		status, err := restoreContainer(context, config, imagePath)
		if err != nil {
			fatal(err)
		}
		os.Exit(status)
	},
}

func restoreContainer(context *cli.Context, config *configs.Config, imagePath string) (int, error) {
	//rootuid, err := config.HostUID()
	//if err != nil {
	//fatal(err)
	//}
	rootuid := 0 // XXX
	container, created, err := getOrCreateContainer(context, config)
	if err != nil {
		return -1, err
	}
	defer destoryMaybe(container, created)
	process := &libcontainer.Process{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	tty, err := newTty(context, process, rootuid)
	if err != nil {
		return -1, err
	}
	defer tty.Close()
	go handleSignals(process, tty)
	err = container.Restore(process, &libcontainer.CriuOpts{
		ImagesDirectory:         imagePath,
		WorkDirectory:           context.String("work-path"),
		TcpEstablished:          context.Bool("tcp-established"),
		ExternalUnixConnections: context.Bool("ext-unix-sk"),
		ShellJob:                context.Bool("shell-job"),
	})
	status, err := process.Wait()
	if err != nil {
		return -1, err
	}
	return utils.ExitStatus(status.Sys().(syscall.WaitStatus)), nil
}

func handleSignals(process *libcontainer.Process, tty *tty) {
	sigc := make(chan os.Signal, 10)
	signal.Notify(sigc)
	tty.resize()
	for sig := range sigc {
		switch sig {
		case syscall.SIGWINCH:
			tty.resize()
		default:
			process.Signal(sig)
		}
	}
}
