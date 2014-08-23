package network

import (
	"fmt"
	"syscall"

	"github.com/docker/libcontainer/system"
	"github.com/docker/libcontainer/utils"
)

func SetNs(path string) error {
	nsFd, err := utils.GetFd(path)
	if err != nil {
		return err
	}
	if err := system.Setns(nsFd, syscall.CLONE_NEWNET); err != nil {
		return fmt.Errorf("failed to setns network namespace: %v", err)
	}
	return nil
}
