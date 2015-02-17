package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/codegangsta/cli"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/libcontainer"
)

var restoreDescription string = `Restore a process tree in a container previously checkpointed with
   the criu(8) utility.

   The container ID is determined by one of the following two methods
   in the order described:

      1. Command line arugment
      2. Last pathname component of the data_path environment variable

   If method 1 is used, the libcontainer's home directory must be
   specified in the LIBCONTAINER_DIR environment variable.

   The user has to specify an image home directory by setting the
   CRIU_IMG_HOME_DIR environment variable.  Within this directory,
   nsinit expects to find the container's image files saved by criu(8)
   in the <container_id>/criu_img subdirectory.

   Restore currently assumes that it's restoring a container using the
   AUFS filesystem.  As such, it expects to find an AUFS directory tree
   at "../../aufs" relative to LIBCONTAINER_DIR.  Support for other
   filesystems types such as VFS and UnionFS can be added on a need basis.

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
   # docker ps -a -lq --no-trunc
   281ab0098269e515e3f81661c3cd6272abb640cf352efc64b3b98cc2470f3944
   # nsinit restore 281ab0098269e515e3f81661c3cd6272abb640cf352efc64b3b98cc2470f3944
   restore succeeded
   # `

var restoreCommand = cli.Command{
	Name:        "restore",
	Usage:       "restore a container",
	Action:      restoreAction,
	Description: restoreDescription,
	Flags: []cli.Flag{
		cli.BoolFlag{Name: "verbose, v", Usage: "enable verbose mode"},
	},
}

func restoreAction(context *cli.Context) {
	if len(context.Args()) > 1 {
		log.Fatal("Too many command line arguments\n")
	}

	// Get container ID and set dataPath if needed.
	containerId := getContainerId(context)

	// If there is a state.json file, the container already exists.
	state, err := libcontainer.GetState(dataPath)
	if err == nil {
		log.Fatalf("Container already running (check pid %d)", state.InitPid)
	}

	// Decode container.json in the criu image directory
	// that was saved there during checkpoint.  We need to
	// get external bind mount paths from it.
	imageDir := getImageDir(containerId)
	f, err := os.Open(filepath.Join(imageDir, "container.json"))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var container *libcontainer.Config
	err = json.NewDecoder(f).Decode(&container)
	if err != nil {
		log.Fatal(err)
	}

	// Mount the container's filesystem if it's not already mounted.
	if !rootFsMounted(container) {
		// NOTE: Because the container's filesystem type is not
		//       specified in either container.json or state.json,
		//       we assume here that it's the default AUFS.  If
		//       using other filesystem types (VFS, UnionFS, etc.),
		//       for now make sure that it's already mounted.
		//       Support will be added in a subsequent commit.
		err = mountAufsRoot(containerId, container.RootFs, context.Bool("verbose"))
		if err != nil {
			log.Fatal(err)
		}
	}

	// Run criu and exit on error because our caller doesn't take return value.
	err = runCriu(context, container, containerId, imageDir, 0)
	if err != nil {
		log.Fatal(err)
	}
}

func rootFsMounted(container *libcontainer.Config) bool {
	mountInfos, err := mount.GetMounts()
	if err != nil {
		log.Fatal(err)
	}

	for _, mount := range mountInfos {
		if mount.Mountpoint == container.RootFs {
			return true
		}
	}
	return false
}

func mountAufsRoot(containerId, rootFs string, verbose bool) error {
	aufsDir := filepath.Join(libcontainerDir, "../../aufs")

	// Read filesystem's AUFS branch IDs.
	f, err := os.Open(filepath.Join(aufsDir, "layers", containerId))
	if err != nil {
		return err
	}
	defer f.Close()
	aufsBranches := filepath.Join(aufsDir, "diff", containerId)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		aufsBranches = fmt.Sprintf("%s:%s", aufsBranches, filepath.Join(aufsDir, "diff", scanner.Text()))
	}
	err = scanner.Err()
	if err != nil {
		return err
	}

	// Build the command line.
	args := []string{"-t", "aufs", "-o", "br=" + aufsBranches, "none", rootFs}

	// Mount the container's filesystem.
	cmd := "mount"
	if verbose {
		log.Printf("%s %v\n", cmd, args)
	}
	output, err := exec.Command(cmd, args...).CombinedOutput()
	if verbose && len(output) > 0 {
		log.Printf("%s\n", output)
	}
	return err
}
