// +build linux

package namespaces

import (
	"errors"
	"os"
	"syscall"

	"github.com/docker/libcontainer"
)

type initError struct {
	Message string `json:"message,omitempty"`
}

func (i initError) Error() string {
	return i.Message
}

var namespaceInfo = map[libcontainer.NamespaceType]int{
	libcontainer.NEWNET:  syscall.CLONE_NEWNET,
	libcontainer.NEWNS:   syscall.CLONE_NEWNS,
	libcontainer.NEWUSER: syscall.CLONE_NEWUSER,
	libcontainer.NEWIPC:  syscall.CLONE_NEWIPC,
	libcontainer.NEWUTS:  syscall.CLONE_NEWUTS,
	libcontainer.NEWPID:  syscall.CLONE_NEWPID,
}

// New returns a newly initialized Pipe for communication between processes
func newInitPipe() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

// getNamespaceFlags parses the container's Namespaces options to set the correct
// flags on clone, unshare, and setns
func getNamespaceFlags(namespaces libcontainer.Namespaces, onlyNew bool) (flag int) {
	for _, v := range namespaces {
		if onlyNew && v.Path != "" {
			continue
		}
		flag |= namespaceInfo[v.Type]
	}
	return flag
}

// Check NamespaceFlags with proper namespace.
func checkNamespaceFlags(container *libcontainer.Config) (int, error) {
	cloneFlags := getNamespaceFlags(container.Namespaces, true)

	if ((cloneFlags & syscall.CLONE_NEWNET) == 0) &&
		(len(container.Networks) != 0 || len(container.Routes) != 0) {
		return cloneFlags, errors.New("unable to apply network parameters without network namespace")
	}
	if (cloneFlags & syscall.CLONE_NEWNS) == 0 {
		if container.MountConfig != nil {
			return cloneFlags, errors.New("mount_config is set without mount namespace")
		}
		if container.RestrictSys {
			return cloneFlags, errors.New("unable to restrict access to sysctl without mount namespace")
		}
	}
	if (cloneFlags & syscall.CLONE_NEWUTS) == 0 {
		return cloneFlags, errors.New("unable to set the hostname without UTS namespace")
	}

	return cloneFlags, nil
}
