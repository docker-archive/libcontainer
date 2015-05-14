package main

import (
	"encoding/json"
	"fmt"

	"github.com/codegangsta/cli"
)

var stateCommand = cli.Command{
	Name:  "state",
	Usage: "get the container's current state",
	Flags: []cli.Flag{
		idFlag,
	},
	Action: func(context *cli.Context) {
		container, err := getContainer(context)
		if err != nil {
			fatal(err)
		}
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
