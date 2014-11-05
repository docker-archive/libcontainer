// +build linux

package console

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type Console interface {
	// Master returns the master pair of the TTY
	Master() *os.File
	// Path is the path to the slave pair of the TTY
	Path() string
	// Dup opens the slave and dup2 STDIN, STDOUT, STDERR of the current process
	Dup() error
	// Setctty sets ctty for the current process
	Setctty() error
	// Bind binds the console to the rootfs applying the current mount label
	Bind(rootfs, mountLabel string) error
}

// CreateMasterAndConsole will open /dev/ptmx on the host and retreive the
// pts name for use as the pty slave inside the container
func New() (Console, error) {
	master, err := os.OpenFile("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	console, err := ptsname(master)
	if err != nil {
		return nil, err
	}
	if err := unlockpt(master); err != nil {
		return nil, err
	}

	return &linuxConsole{
		master: master,
		path:   console,
	}, nil
}

func FromPath(path string) Console {
	if path == "" {
		return Null()
	}
	return &linuxConsole{
		path: path,
	}
}

func Null() Console {
	return &nullConsole{}
}

// unlockpt unlocks the slave pseudoterminal device corresponding to the master pseudoterminal referred to by f.
// unlockpt should be called before opening the slave side of a pseudoterminal.
func unlockpt(f *os.File) error {
	var u int32
	return ioctl(f.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&u)))
}

// ptsname retrieves the name of the first available pts for the given master.
func ptsname(f *os.File) (string, error) {
	var n int32
	if err := ioctl(f.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		return "", err
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}

// openPtmx opens /dev/ptmx, i.e. the PTY master.
func openPtmx() (*os.File, error) {
	// O_NOCTTY and O_CLOEXEC are not present in os package so we use the syscall's one for all.
	return os.OpenFile("/dev/ptmx", syscall.O_RDONLY|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
}

// openTerminal is a clone of os.OpenFile without the O_CLOEXEC
// used to open the pty slave inside the container namespace
func openTerminal(name string, flag int) (*os.File, error) {
	r, e := syscall.Open(name, flag, 0)
	if e != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: e}
	}
	return os.NewFile(uintptr(r), name), nil
}

func ioctl(fd uintptr, flag, data uintptr) error {
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, flag, data); err != 0 {
		return err
	}
	return nil
}
