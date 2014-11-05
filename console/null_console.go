package console

import "os"

type nullConsole struct {
}

func (n *nullConsole) Path() string {
	return ""
}

func (n *nullConsole) Master() *os.File {
	return nil
}

func (n *nullConsole) Dup() error {
	return nil
}

func (n *nullConsole) Setctty() error {
	return nil
}

func (n *nullConsole) Bind(rootfs, mountLabel string) error {
	return nil
}
