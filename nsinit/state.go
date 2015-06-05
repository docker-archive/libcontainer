package main

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
)

var stateCommand = cli.Command{
	Name:   "state",
	Usage:  "dump the container state",
	Before: containerPreload,
	Flags: []cli.Flag{
		idFlag,
	},
	Action: func(context *cli.Context) {
		state, err := container.State()
		if err != nil {
			fatal(err)
		}
		data, err := json.MarshalIndent(state, "", "\t")
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%s", data)
	},
}

var pauseCommand = cli.Command{
	Name:   "pause",
	Usage:  "pause the container",
	Before: containerPreload,
	Flags: []cli.Flag{
		idFlag,
	},
	Action: func(context *cli.Context) {
		if err := container.Pause(); err != nil {
			logrus.Fatal(err)
		}
	},
}

var unpauseCommand = cli.Command{
	Name:   "unpause",
	Usage:  "unpause the container",
	Before: containerPreload,
	Flags: []cli.Flag{
		idFlag,
	},
	Action: func(context *cli.Context) {
		if err := container.Resume(); err != nil {
			logrus.Fatal(err)
		}
	},
}
