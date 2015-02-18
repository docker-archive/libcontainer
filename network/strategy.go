// +build linux

package network

import (
	"errors"
	"sync"
)

var (
	ErrNotValidStrategyType = errors.New("not a valid network strategy type")

	strategiesMtx sync.RWMutex
	strategies    = map[string]NetworkStrategy{
		"veth":     &Veth{},
		"loopback": &Loopback{},
	}
)

// NetworkStrategy represents a specific network configuration for
// a container's networking stack
type NetworkStrategy interface {
	Create(*Network, int, *NetworkState) error
	Initialize(*Network, *NetworkState) error
}

// GetStrategy returns the specific network strategy for the
// provided type.  If no strategy is registered for the type an
// ErrNotValidStrategyType is returned.
func GetStrategy(tpe string) (NetworkStrategy, error) {
	strategiesMtx.RLock()
	defer strategiesMtx.RUnlock()
	s, exists := strategies[tpe]
	if !exists {
		return nil, ErrNotValidStrategyType
	}
	return s, nil
}

// AddStrategy registers a network strategy to be used for the
// provided type. If there is a strategy already associated with
// that type, it will be overridden. Multiple goroutines can
// safely call AddStrategy.
func AddStrategy(tpe string, strategy NetworkStrategy) {
	strategiesMtx.Lock()
	defer strategiesMtx.Unlock()
	strategies[tpe] = strategy
}
