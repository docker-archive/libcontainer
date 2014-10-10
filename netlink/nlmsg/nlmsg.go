// Package nlmsg provides access to low level Netlink sockets and messages.
//
// Actual implementations are in:
// netlink_linux.go
// netlink_darwin.go
package nlmsg

import (
	"errors"
)

var (
	ErrWrongSockType = errors.New("Wrong socket type")
	ErrShortResponse = errors.New("Got short response from netlink")
)
