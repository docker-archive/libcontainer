package main

import (
	"fmt"
	"os"

	"github.com/codegangsta/cli"
)

var checkpointCommand = cli.Command{
	Name:  "checkpoint",
	Usage: "checkpoint a running container",
	Flags: []cli.Flag{
		cli.StringFlag{Name: "id", Value: "nsinit", Usage: "specify the ID for a container"},
		cli.StringFlag{Name: "image-path", Value: "", Usage: "path where to save images"},
		cli.StringFlag{Name: "page-server", Value: "", Usage: "IP address of the page server"},
		cli.StringFlag{Name: "port", Value: "", Usage: "port number of the page server"},
	},
	Action: func(context *cli.Context) {
		imagePath := context.String("image-path")
		if imagePath == "" {
			fatal(fmt.Errorf("The --image-path option isn't specified"))
		}
		container, err := getContainer(context)
		if err != nil {
			fatal(err)
		}
		// Since a container can be C/R'ed multiple times,
		// the checkpoint directory may already exist.
		if err := os.Mkdir(imagePath, 0655); err != nil && !os.IsExist(err) {
			fatal(err)
		}

		// The dump image can be sent to a criu page server
		var port string
		psAddress := context.String("page-server")
		if psAddress != "" {
			port = context.String("port")
			if port == "" {
				fatal(fmt.Errorf("The --port number isn't specified"))
			}
		}

		if err := container.Checkpoint(imagePath, psAddress, port); err != nil {
			fatal(err)
		}
	},
}
