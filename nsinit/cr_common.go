package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/namespaces"
)

// Refer to the description message at the beginning of this file to
// see how we get the container ID.
func getContainerId(context *cli.Context) string {
	if len(context.Args()) == 1 {
		// dataPath may have been initialized from data_path if
		// in environment (if it was set).  But if a container
		// ID is specified on the command line, dataPath will be
		// reinitialized here from LIBCONTAINER_DIR environment
		// variable and the specified container ID.
		containerId := context.Args()[0]
		if libcontainerDir == "" {
			log.Fatal("LIBCONTAINER_DIR not set")
		}
		dataPath = filepath.Join(libcontainerDir, containerId)
		return containerId
	}

	if dataPath == "" {
		// If the container has been checkpointed, the directory
		// where its container.json file existed has been removed.
		// So for restore, we cannot get the container ID from
		// the cwd pathname.
		if context.Command.Name == "restore" {
			log.Fatal("Specify container ID as an argument or set data_path env var")
		}

		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		dataPath = cwd
	}

	// Extract container ID from the pathname.
	containerId := filepath.Base(dataPath)
	if containerId == "" {
		log.Fatal("Cannot determine container ID")
	}

	return containerId
}

// Return the directory pathname where CRIU should save and retrieve
// its image files.
func getImageDir(containerId string) string {
	p := os.Getenv("CRIU_IMG_HOME_DIR")
	if p == "" {
		log.Fatal("CRIU_IMG_HOME_DIR not set")
	}
	return filepath.Join(p, containerId, "criu_img")
}

// Common code for checkpoint and restore.
func runCriu(context *cli.Context, container *libcontainer.Config, containerId, imageDir string, initPid int) error {
	verbose := context.Bool("verbose")
	cmd := context.Command.Name

	criuBinary := os.Getenv("CRIU_BINARY")
	if criuBinary == "" {
		criuBinary = "criu"
	}

	var err error
	if cmd == "checkpoint" {
		err = namespaces.Checkpoint(criuBinary, container, imageDir, initPid, verbose)
	} else {
		err = namespaces.Restore(criuBinary, container, imageDir, verbose)
	}
	if !verbose {
		return err
	}

	if err == nil {
		fmt.Printf("%s succeeded\n", cmd)
	} else {
		fmt.Printf("%s failed: %s\n", cmd, err)
		var logFile string
		if cmd == "checkpoint" {
			logFile = filepath.Join(imageDir, namespaces.CheckpointLog)
		} else {
			logFile = filepath.Join(imageDir, namespaces.RestoreLog)
		}
		fmt.Printf("Cause of failure may be in %s\n", logFile)
	}
	return err
}
