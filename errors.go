package libcontainer

import "errors"

var (
	ErrProcessCommandExists = errors.New("process already contains a command")
	ErrUnkownNamespace      = errors.New("unknown namespace")
)
