package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
)

var checkpointDescription string = `Checkpoint a process tree running in a container with the criu(8)
   utility.

   The container ID is determined by one of the following three methods
   in the order described:

      1. Command line argument
      2. Last pathname component of the data_path environment variable
      3. Last pathname component of the current working directory

   If method 1 is used, the libcontainer's home directory must be
   specified in the LIBCONTAINER_DIR environment variable.

   Nsinit expects to find the container's container.json and state.json
   files in the container subdirectory of the libcontainer's home
   directory.

   The user has to specify an image home directory for criu(8) by setting
   the CRIU_IMG_HOME_DIR environment variable.  Within this directory,
   a container's image files will be saved in <container_id>/criu_img
   subdirectory.

   Returns 0 on success.  On error, prints an error message and returns
   a non-zero code.

ENVIRONMENT:
   CRIU_BINARY          criu binary to execute, if not set "criu" is assumed
   CRIU_IMG_HOME_DIR    criu image home directory
   LIBCONTAINER_DIR     libcontainer home directory
   data_path            directory pathname of container.json (no trailing /)
   log                  pathname where to log

EXAMPLE:
   # export LIBCONTAINER_DIR=/var/lib/docker/execdriver/native
   # export CRIU_IMG_HOME_DIR=/var/lib/docker/containers
   # docker ps -lq --no-trunc
   281ab0098269e515e3f81661c3cd6272abb640cf352efc64b3b98cc2470f3944
   # nsinit checkpoint 281ab0098269e515e3f81661c3cd6272abb640cf352efc64b3b98cc2470f3944
   checkpoint succeeded
   # `

var checkpointCommand = cli.Command{
	Name:        "checkpoint",
	Usage:       "checkpoint a container",
	Action:      checkpointAction,
	Description: checkpointDescription,
	Flags: []cli.Flag{
		cli.BoolFlag{Name: "verbose, v", Usage: "enable verbose mode"},
	},
}

func checkpointAction(context *cli.Context) {
	if len(context.Args()) > 1 {
		log.Fatal("Too many command line arguments\n")
	}

	// Get container ID and set dataPath if needed.
	containerId := getContainerId(context)

	// Load the container.json file to verify that we have
	// a valid container.
	container, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Get the init PID of the process tree from state.json.
	state, err := libcontainer.GetState(dataPath)
	if err != nil {
		log.Fatal(err)
	}
	initPid := state.InitPid
	if initPid == 0 {
		log.Fatal("Container's init PID is uninitialized\n")
	}

	// Create an image directory for this container (which
	// may already exist from a previous checkpoint).
	imageDir := getImageDir(containerId)
	err = os.MkdirAll(imageDir, 0700)
	if err != nil {
		log.Fatal(err)
	}

	// Copy container.json in the criu image directory for
	// later use during restore.
	copyFile(filepath.Join(dataPath, "container.json"), filepath.Join(imageDir, "container.json"))
	if err != nil {
		log.Fatal(err)
	}

	// Run criu and exit on error because our caller doesn't take return value.
	err = runCriu(context, container, containerId, imageDir, initPid)
	if err != nil {
		log.Fatal(err)
	}
}
