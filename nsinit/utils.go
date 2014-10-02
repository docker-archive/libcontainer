package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/syncpipe"
)

// rFunc is a function registration for calling after an execin
type rFunc struct {
	Usage  string
	Action func(*libcontainer.Config, []string)
}

func loadConfig() (*libcontainer.Config, error) {
	f, err := os.Open(filepath.Join(dataPath, "container.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var container *libcontainer.Config
	if err := json.NewDecoder(f).Decode(&container); err != nil {
		return nil, err
	}

	return container, nil
}

func openLog(name string) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0755)
	if err != nil {
		return err
	}

	log.SetOutput(f)

	return nil
}

func findUserArgs() []string {
	i := 0
	for _, a := range os.Args {
		i++

		if a == "--" {
			break
		}
	}

	return os.Args[i:]
}

// loadConfigFromFd loads a container's config from the sync pipe that is provided by
// fd 3 when running a process
func loadConfigFromFd() (*libcontainer.Config, error) {
	syncPipe, err := syncpipe.NewSyncPipeFromFd(0, 3)
	if err != nil {
		return nil, err
	}

	var config *libcontainer.Config
	if err := syncPipe.ReadFromParent(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func preload(context *cli.Context) error {
	if logPath != "" {
		if err := openLog(logPath); err != nil {
			return err
		}
	}

	return nil
}

func runFunc(f *rFunc) {
	userArgs := findUserArgs()

	config, err := loadConfigFromFd()
	if err != nil {
		log.Fatalf("unable to receive config from sync pipe: %s", err)
	}

	f.Action(config, userArgs)
}

func copyFile(srcFile, dstFile string) error {
	src, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}
