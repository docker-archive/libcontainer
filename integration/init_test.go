package integration

import (
	"log"
	"os"
	"runtime"

	"github.com/docker/libcontainer/console"
	"github.com/docker/libcontainer/namespaces"
	"github.com/docker/libcontainer/syncpipe"
)

// init runs the libcontainer initialization code because of the busybox style needs
// to work around the go runtime and the issues with forking
func init() {
	if len(os.Args) < 2 || os.Args[1] != "init" {
		return
	}
	runtime.LockOSThread()

	container, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	rootfs, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	syncPipe, err := syncpipe.NewSyncPipeFromFd(0, 3)
	if err != nil {
		log.Fatalf("unable to create sync pipe: %s", err)
	}

	if err := namespaces.Init(container, rootfs, console.FromPath(""), syncPipe, os.Args[3:]); err != nil {
		log.Fatalf("unable to initialize for container: %s", err)
	}
	os.Exit(1)
}
