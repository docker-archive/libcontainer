package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
)

var pauseCommand = cli.Command{
	Name:  "pause",
	Usage: "pause the container",
	Flags: []cli.Flag{
		idFlag,
	},
	Action: func(context *cli.Context) {
		container, err := getContainer(context)
		if err != nil {
			logrus.Fatal(err)
		}
		if err = container.Pause(); err != nil {
			logrus.Fatal(err)
		}
	},
}

var unpauseCommand = cli.Command{
	Name:  "unpause",
	Usage: "unpause the container",
	Flags: []cli.Flag{
		idFlag,
	},
	Action: func(context *cli.Context) {
		container, err := getContainer(context)
		if err != nil {
			logrus.Fatal(err)
		}
		if err = container.Resume(); err != nil {
			logrus.Fatal(err)
		}
	},
}
