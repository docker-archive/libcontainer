// +build linux

package network

import (
	"fmt"
	"syscall"

	"github.com/docker/libcontainer/system"
)

//  crosbymichael: could make a network strategy that instead of returning veth pair names it returns a pid to an existing network namespace
type NetNS struct {
}

func (v *NetNS) Create(n *Network, networkState *NetworkState) error {
	networkState.NetnsFd = n.NetnsFd
	return nil
}

func (v *NetNS) Initialize(config *Network, networkState *NetworkState) error {
	if networkState.NetnsFd == 0 {
		return fmt.Errorf("netns fd is not specified in NetworkState")
	}

	if err := system.Setns(uintptr(networkState.NetnsFd), syscall.CLONE_NEWNET); err != nil {
		return fmt.Errorf("failed to setns current network namespace: %v", err)
	}

	return nil
}
