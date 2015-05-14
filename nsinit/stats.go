package main

import (
	"encoding/json"
	"fmt"

	"github.com/codegangsta/cli"
)

var statsCommand = cli.Command{
	Name:  "stats",
	Usage: "display statistics for the container",
	Flags: []cli.Flag{
		idFlag,
	},
	Action: func(context *cli.Context) {
		container, err := getContainer(context)
		if err != nil {
			fatal(err)
		}
		stats, err := container.Stats()
		if err != nil {
			fatal(err)
		}
		data, err := json.MarshalIndent(stats, "", "\t")
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%s", data)
	},
}
