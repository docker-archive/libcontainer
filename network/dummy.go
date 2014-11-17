// +build linux

package network

import (
	"fmt"

	"github.com/docker/libcontainer/netlink"
)

type Dummy struct {
}

func (d *Dummy) Create(n *Network, nspid int, networkState *NetworkState) error {
	name := n.DummyName
	if name == "" {
		return fmt.Errorf("dummy interface name is not specified")
	}

	if err := netlink.NetworkLinkAdd(name, "dummy"); err != nil {
		return fmt.Errorf("Unable to create dummy interface %s: %s", name, err)
	}
	if err := InterfaceUp(name); err != nil {
		return err
	}
	if err := SetInterfaceInNamespacePid(name, nspid); err != nil {
		return err
	}

	return nil
}

func (d *Dummy) Initialize(config *Network, networkState *NetworkState) error {
	name := config.DummyName
	if name == "" {
		return fmt.Errorf("dummy interface name is not specified")
	}

	if err := InterfaceDown(name); err != nil {
		return fmt.Errorf("interface down %s %s", name, err)
	}
	if config.MacAddress != "" {
		if err := SetInterfaceMac(name, config.MacAddress); err != nil {
			return fmt.Errorf("set %s mac %s", name, err)
		}
	}
	if err := SetInterfaceIp(name, config.Address); err != nil {
		return fmt.Errorf("set %s ip %s", name, err)
	}
	if config.IPv6Address != "" {
		if err := SetInterfaceIp(name, config.IPv6Address); err != nil {
			return fmt.Errorf("set %s ipv6 %s", name, err)
		}
	}
	if err := SetMtu(name, config.Mtu); err != nil {
		return fmt.Errorf("set %s mtu to %d %s", name, config.Mtu, err)
	}
	if err := InterfaceUp(name); err != nil {
		return fmt.Errorf("%s up %s", name, err)
	}
	return nil
}
