package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
)

const (
	version = "4"
	usage   = `standalone container runtime

nsinit integrates well with existing process supervisors to provide a production container runtime environment for
applications.  It can be used with your existing process monitoring tools and the container will be spawned as direct 
child of the process supervisor.  nsinit can be used to manage the lifetime of a single container.

Execute a simple container in your shell by running: 

    nsinit exec --tty sh

Made with ♥ by docker
`
)

var idFlag = cli.StringFlag{
	Name:  "id",
	Value: getDefaultID(),
	Usage: "specify the ID to be used for the container",
}

func main() {
	app := cli.NewApp()
	app.Name = "nsinit"
	app.Usage = usage
	app.Version = version
	app.Authors = []cli.Author{
		{
			Name:  "@crosbymichael",
			Email: "michael@docker.com",
		},
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{Name: "debug", Usage: "enable debug output for logging"},
		cli.StringFlag{Name: "criu", Value: "criu", Usage: "path to the criu binary for checkpoint and restore"},
		cli.StringFlag{Name: "root", Value: "/var/run/nsinit", Usage: "root directory for storage of container state (this should be located in tmpfs)"},
	}
	app.Commands = []cli.Command{
		checkpointCommand,
		configCommand,
		eventsCommand,
		execCommand,
		initCommand,
		pauseCommand,
		restoreCommand,
		stateCommand,
		unpauseCommand,
	}
	app.Before = func(context *cli.Context) error {
		if context.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
