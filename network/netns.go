// +build linux

package network

import "fmt"

//  crosbymichael: could make a network strategy that instead of returning veth pair names it returns a pid to an existing network namespace
type NetNS struct {
}

func (v *NetNS) Create(n *Network, nspath string, networkState *NetworkState) error {
	networkState.NsPath = n.NsPath
	return nil
}

func (v *NetNS) Initialize(config *Network, networkState *NetworkState) error {
	if networkState.NsPath == "" {
		return fmt.Errorf("nspath does is not specified in NetworkState")
	}

	if err := SetNs(networkState.NsPath); err != nil {
		return err
	}

	f.Close()
	return nil
}
