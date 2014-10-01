package namespaces

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/docker/libcontainer"
)

// Restore the specified container (previously checkpointed) using the
// criu(8) utility.
func Restore(criuBinary string, container *libcontainer.Config, imageDir string, verbose bool) error {
	// Prepare command line arguments.
	args := []string{
		"restore", "-d", "-v4",
		"-D", imageDir, "-o", RestoreLog,
		"--root", container.RootFs,
		"--manage-cgroups", "--evasive-devices",
	}
	for _, mountpoint := range container.MountConfig.Mounts {
		args = append(args, "--ext-mount-map", fmt.Sprintf("%s:%s", mountpoint.Destination, mountpoint.Source))
	}

	// Execute criu to restore.
	if verbose {
		log.Printf("Running CRIU: %s %v\n", criuBinary, args)
	}
	output, err := exec.Command(criuBinary, args...).CombinedOutput()
	if verbose && len(output) > 0 {
		log.Printf("%s\n", output)
	}
	return err
}
