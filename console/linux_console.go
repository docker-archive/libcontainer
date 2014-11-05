package console

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/docker/libcontainer/label"
	"github.com/docker/libcontainer/system"
)

type linuxConsole struct {
	master *os.File
	path   string
}

func (c *linuxConsole) Master() *os.File {
	return c.master
}

func (c *linuxConsole) Path() string {
	return c.path
}

// Dup opens the console at the Path and dup2's the fd to STDIN, STDOUT, STDERR
func (c *linuxConsole) Dup() error {
	slave, err := openTerminal(c.path, syscall.O_RDWR)
	if err != nil {
		return fmt.Errorf("open terminal %s", err)
	}
	fd := int(slave.Fd())
	for i := 0; i < 3; i++ {
		if err := syscall.Dup2(fd, i); err != nil {
			return err
		}
	}
	return nil
}

func (c *linuxConsole) Setctty() error {
	return system.Setctty()
}

// Bind initializes the proper /dev/console inside the rootfs path
func (c *linuxConsole) Bind(rootfs, mountLabel string) error {
	oldMask := syscall.Umask(0000)
	defer syscall.Umask(oldMask)

	if err := os.Chmod(c.path, 0600); err != nil {
		return err
	}
	if err := os.Chown(c.path, 0, 0); err != nil {
		return err
	}
	if err := label.SetFileLabel(c.path, mountLabel); err != nil {
		return fmt.Errorf("set file label %s %s", c.path, err)
	}
	dest := filepath.Join(rootfs, "dev/console")
	f, err := os.Create(dest)
	if err == nil {
		f.Close()
	}
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("create %s %s", dest, err)
	}
	return syscall.Mount(c.path, dest, "bind", syscall.MS_BIND, "")
}
