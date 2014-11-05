// +build linux

package mount

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/libcontainer/console"
)

func SetupPtmx(rootfs string, c console.Console, mountLabel string) error {
	ptmx := filepath.Join(rootfs, "dev/ptmx")
	if err := os.Remove(ptmx); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink("pts/ptmx", ptmx); err != nil {
		return fmt.Errorf("symlink dev ptmx %s", err)
	}
	return c.Bind(rootfs, mountLabel)
}
