package namespaces

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"

	"github.com/docker/libcontainer"
)

const (
	CheckpointLog = "dump.log"
	RestoreLog    = "restore.log"
)

// Checkpoint the specified container using the criu(8) utility.
func Checkpoint(criuBinary string, container *libcontainer.Config, imageDir string, initPid int, verbose bool) error {
	// Prepare command line arguments.
	args := []string{
		"dump", "-v4",
		"-D", imageDir, "-o", CheckpointLog,
		"--root", container.RootFs,
		"--manage-cgroups", "--evasive-devices",
		"-t", strconv.Itoa(initPid),
	}
	for _, mountpoint := range container.MountConfig.Mounts {
		args = append(args, "--ext-mount-map", fmt.Sprintf("%s:%s", mountpoint.Destination, mountpoint.Destination))
	}

	// Execute criu to checkpoint.
	if verbose {
		log.Printf("Running CRIU: %s %v\n", criuBinary, args)
	}
	output, err := exec.Command(criuBinary, args...).CombinedOutput()
	if verbose && len(output) > 0 {
		log.Printf("%s\n", output)
	}
	return err
}
