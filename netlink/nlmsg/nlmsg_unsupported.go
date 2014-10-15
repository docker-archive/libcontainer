// +build !linux

package nlmsg

import (
	"errors"
)

var (
	ErrNotImplemented = errors.New("not implemented")
)
