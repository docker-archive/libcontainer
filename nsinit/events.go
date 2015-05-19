package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
)

// event struct for encoding the event data to json.
type event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

var eventsCommand = cli.Command{
	Name:  "events",
	Usage: "display container events such as OOM notifications and cpu, memeory, IO, and network stats",
	Flags: []cli.Flag{
		idFlag,
		cli.DurationFlag{Name: "interval", Value: 5 * time.Second, Usage: "set the stats collection interval"},
	},
	Action: func(context *cli.Context) {
		container, err := getContainer(context)
		if err != nil {
			logrus.Fatal(err)
		}
		var (
			stats  = make(chan *libcontainer.Stats, 1)
			events = make(chan *event)
		)
		go func() {
			enc := json.NewEncoder(os.Stdout)
			for e := range events {
				if err := enc.Encode(e); err != nil {
					logrus.Error(err)
				}
			}
		}()
		go func() {
			for _ = range time.Tick(context.Duration("interval")) {
				s, err := container.Stats()
				if err != nil {
					logrus.Error(err)
					continue
				}
				stats <- s
			}
		}()
		n, err := container.NotifyOOM()
		if err != nil {
			logrus.Fatal(err)
		}
		for {
			select {
			case _, ok := <-n:
				if ok {
					// this means an oom event was received, if it is !ok then
					// the channel was closed because the container stopped and
					// the cgroups no longer exist.
					events <- &event{Type: "oom"}
				} else {
					n = nil
				}
			case s := <-stats:
				events <- &event{Type: "stats", Data: s}
			}
			if n == nil {
				return
			}
		}
	},
}
