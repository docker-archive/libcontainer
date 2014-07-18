package nsinit

import (
	"log"
	"os"

	"github.com/codegangsta/cli"
)

var logger *log.Logger

func preload(context *cli.Context) (err error) {
	logger, err = openLog()

	return err
}

func NsInit() {
	app := cli.NewApp()
	app.Name = "nsinit"
	app.Usage = "just workin on containers"
	app.Version = "0.2"
	app.Author = "libcontainer maintainers"

	app.Before = preload
	app.Commands = []cli.Command{
		execCommand,
		initCommand,
		statsCommand,
		configCommand,
		nsenterCommand,
		pauseCommand,
		unpauseCommand,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
