package main

import (
	"os"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
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
	handler := newSignalHandler(tty)
	defer handler.Close()
	err = container.Restore(process, &libcontainer.CriuOpts{
		ImagesDirectory:         imagePath,
		WorkDirectory:           context.String("work-path"),
		TcpEstablished:          context.Bool("tcp-established"),
		ExternalUnixConnections: context.Bool("ext-unix-sk"),
		ShellJob:                context.Bool("shell-job"),
	})
	return handler.process(process)
}
