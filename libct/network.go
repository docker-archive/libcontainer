// +build linux

package libct

import (
	"errors"
	"fmt"

	_libct "github.com/xemul/libct/go"
	"github.com/docker/libcontainer/network"
	"github.com/docker/libcontainer/utils"
)

var (
	ErrNotValidStrategyType = errors.New("not a valid network strategy type")
)

var strategies = map[string]NetworkStrategy{
	"veth":     &Veth{},
	"loopback": &Loopback{},
}

// NetworkStrategy represents a specific network configuration for
// a container's networking stack
type NetworkStrategy interface {
	Create(*_libct.Container, *network.Network, *network.NetworkState) error
}

// GetStrategy returns the specific network strategy for the
// provided type.  If no strategy is registered for the type an
// ErrNotValidStrategyType is returned.
func GetStrategy(tpe string) (NetworkStrategy, error) {
	s, exists := strategies[tpe]
	if !exists {
		return nil, ErrNotValidStrategyType
	}
	return s, nil
}

// Veth is a network strategy that uses a bridge and creates
// a veth pair, one that stays outside on the host and the other
// is placed inside the container's namespace
type Veth struct {
}

const defaultDevice = "eth0"

func (v *Veth) Create(ct *_libct.Container, n *network.Network, networkState *network.NetworkState) error {
	var (
		bridge = n.Bridge
		prefix = n.VethPrefix
	)
	if bridge == "" {
		return fmt.Errorf("bridge is not specified")
	}
	if prefix == "" {
		return fmt.Errorf("veth prefix is not specified")
	}
	name1, err := utils.GenerateRandomName(prefix, 4)
	if err != nil {
		return err
	}
	networkState.VethHost = name1
	networkState.VethChild = defaultDevice

	dev, err := ct.AddNetVeth(name1, defaultDevice)
	if err != nil {
		return err
	}

	if err := dev.SetMtu(n.Mtu); err != nil {
		return err
	}

	if err := dev.AddIpAddr(n.Address); err != nil {
		return err
	}

	host_dev, err := dev.GetPeer()
	if err != nil {
		return err
	}

	if err := host_dev.SetMaster(bridge); err != nil {
		return err
	}

	if n.Gateway != "" {
		r, err := ct.AddRoute()
		if err != nil {
			return err
		}
		r.SetDst("default")
		nh, err := r.AddNextHop()
		if err != nil {
			return err
		}
		nh.SetDev(defaultDevice)
		nh.SetGateway(n.Gateway)
	}

	return nil
}

// Loopback is a network strategy that provides a basic loopback device
type Loopback struct {
}

func (l *Loopback) Create(*_libct.Container, *network.Network, *network.NetworkState) error {
	return nil
}
