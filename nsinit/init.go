package main

import (
	"runtime"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	_ "github.com/docker/libcontainer/nsenter"
)

var initCommand = cli.Command{
	Name:  "init",
	Usage: "**internal command for setting up the container's namespaces, this should not be directly invoked**",
	Action: func(context *cli.Context) {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			fatal(err)
		}
		panic("--this line should never been executed, congradulations--")
	},
}
