package netlink

import (
	"net"
	"strings"
	"testing"
)

func TestAddRemNetworkIp(t *testing.T) {
	var err error

	ifaceString := "lo"
	ip := net.ParseIP("127.0.1.1")
	mask := net.IPv4Mask(255, 255, 255, 255)
	ipNet := &net.IPNet{ip, mask}

	iface, err := net.InterfaceByName(ifaceString)
	if err != nil {
		t.Skip("No 'lo' interface; skipping tests")
	}

	err = NetworkLinkAddIp(iface, ip, ipNet)
	if err != nil {
		t.Fatal(err)
	}

	var found bool

	addrs, _ := iface.Addrs()

	for _, addr := range addrs {
		args := strings.SplitN(addr.String(), "/", 2)
		if args[0] == ip.String() {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Could not locate address '%s' in lo address list.", ip.String())
	}

	err = NetworkLinkRemIp(iface, ip, ipNet)
	if err != nil {
		t.Fatal(err)
	}

	found = false

	addrs, _ = iface.Addrs()

	for _, addr := range addrs {
		args := strings.SplitN(addr.String(), "/", 2)
		if args[0] == ip.String() {
			found = true
			break
		}
	}

	if found {
		t.Fatal("Located address '%s' in lo address list after removal.", ip.String())
	}
}

func TestCreateBridgeWithMac(t *testing.T) {
	if testing.Short() {
		return
	}

	name := "testbridge"

	if err := CreateBridge(name, true); err != nil {
		t.Fatal(err)
	}

	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatal(err)
	}

	// cleanup and tests

	if err := DeleteBridge(name); err != nil {
		t.Fatal(err)
	}

	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatal("expected error getting interface because bridge was deleted")
	}
}

func TestCreateVethPair(t *testing.T) {
	if testing.Short() {
		return
	}

	var (
		name1 = "veth1"
		name2 = "veth2"
	)

	if err := NetworkCreateVethPair(name1, name2); err != nil {
		t.Fatal(err)
	}

	if _, err := net.InterfaceByName(name1); err != nil {
		t.Fatal(err)
	}

	if _, err := net.InterfaceByName(name2); err != nil {
		t.Fatal(err)
	}
}
