// +build libct

package libcontainer

import (
	"errors"

	libct "github.com/avagin/libct/go"
	"github.com/docker/libcontainer/configs"
)

var (
	ErrNotValidStrategyType = errors.New("not a valid network strategy type")
)

// NetworkStrategy represents a specific network configuration for
// a container's networking stack
type libctNetworkStrategy interface {
	create(*libct.Container, *configs.Network) error
}

var libctStrategies = map[string]libctNetworkStrategy{
	"veth":     &libctVeth{},
	"loopback": &libctLoopback{},
}

// GetStrategy returns the specific network strategy for the
// provided type.  If no strategy is registered for the type an
// ErrNotValidStrategyType is returned.
func libctGetStrategy(tpe string) (libctNetworkStrategy, error) {
	s, exists := libctStrategies[tpe]
	if !exists {
		return nil, ErrNotValidStrategyType
	}
	return s, nil
}

// Veth is a network strategy that uses a bridge and creates
// a veth pair, one that stays outside on the host and the other
// is placed inside the container's namespace
type libctVeth struct {
}

func (v *libctVeth) create(ct *libct.Container, n *configs.Network) error {
	dev, err := ct.AddNetVeth(n.HostInterfaceName, n.Name)
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

	if err := host_dev.SetMaster(n.Bridge); err != nil {
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
		nh.SetDev(n.Name)
		nh.SetGateway(n.Gateway)
	}

	return nil
}

// Loopback is a network strategy that provides a basic loopback device
type libctLoopback struct {
}

func (l *libctLoopback) create(*libct.Container, *configs.Network) error {
	// FIXME
	return nil
}
