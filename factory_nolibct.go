// +build !libct

package libcontainer

import "fmt"

func NewLibctFactory(root string) (Factory, error) {
	return nil, newGenericError(fmt.Errorf("libct is not compiled in"), ConfigInvalid)
}
