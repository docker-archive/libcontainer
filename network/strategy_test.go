package network

import "testing"

func TestDefaultStrategiesAvailable(t *testing.T) {
	loopback, err := GetStrategy("loopback")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loopback.(*Loopback); !ok {
		t.Fatalf("invalid default loopback strategy: %#+v", loopback)
	}
	veth, err := GetStrategy("veth")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := veth.(*Veth); !ok {
		t.Fatalf("invalid default veth strategy: %#+v", veth)
	}
}

func TestAllowsNewStrategies(t *testing.T) {
	if _, err := GetStrategy("dummy"); err != ErrNotValidStrategyType {
		t.Fatal("expected 'dummy' not to be registered")
	}
	AddStrategy("dummy", new(dummyStrategy))
	if s, err := GetStrategy("dummy"); err != nil || s == nil {
		t.Fatal("expected 'dummy' to be registered")
	}
}

func TestAllowsStrategiesToBeReplaced(t *testing.T) {
	veth, err := GetStrategy("veth")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := veth.(*Veth); !ok {
		t.Fatalf("invalid default veth strategy: %#+v", veth)
	}
	AddStrategy("veth", new(dummyStrategy))
	veth, err = GetStrategy("veth")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := veth.(*dummyStrategy); !ok {
		t.Fatalf("strategy was not replaced: %#+v", veth)
	}
}

type dummyStrategy struct{}

func (s *dummyStrategy) Create(*Network, int, *NetworkState) error {
	return nil
}
func (s *dummyStrategy) Initialize(*Network, *NetworkState) error {
	return nil
}
