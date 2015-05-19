package main

import (
	"io"
	"os"

	"github.com/codegangsta/cli"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/libcontainer"
)

// newTty creates a new pty for use with the container.
func newTty(context *cli.Context, p *libcontainer.Process, rootuid int) (*tty, error) {
	if context.Bool("tty") {
		console, err := p.NewConsole(rootuid)
		if err != nil {
			return nil, err
		}
		go io.Copy(console, os.Stdin)
		go io.Copy(os.Stdout, console)
		state, err := term.SetRawTerminal(os.Stdin.Fd())
		if err != nil {
			return nil, err
		}
		t := &tty{
			console: console,
			state:   state,
			closers: []io.Closer{
				console,
			},
		}
		p.Stderr = nil
		p.Stdout = nil
		p.Stdin = nil
		return t, nil
	}
	t := &tty{}
	// setup standard pipes so that the TTY of the calling nsinit process
	// is not inherited by the container.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go io.Copy(w, os.Stdin)
	t.closers = append(t.closers, w)
	p.Stdin = r
	if r, w, err = os.Pipe(); err != nil {
		return nil, err
	}
	go io.Copy(os.Stdout, r)
	p.Stdout = w
	t.closers = append(t.closers, r)
	if r, w, err = os.Pipe(); err != nil {
		return nil, err
	}
	go io.Copy(os.Stderr, r)
	p.Stderr = w
	t.closers = append(t.closers, r)
	return t, nil
}

type tty struct {
	console libcontainer.Console
	state   *term.State
	closers []io.Closer
}

func (t *tty) Close() error {
	for _, c := range t.closers {
		c.Close()
	}
	if t.state != nil {
		term.RestoreTerminal(os.Stdin.Fd(), t.state)
	}
	return nil
}

func (t *tty) resize() error {
	if t.console == nil {
		return nil
	}
	ws, err := term.GetWinsize(os.Stdin.Fd())
	if err != nil {
		return err
	}
	return term.SetWinsize(t.console.Fd(), ws)
}
