package nsinit

import (
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/dotcloud/docker/pkg/term"
)

var defaultEnv = cli.StringSlice{
	"HOME=/",
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"HOSTNAME=koye",
	"TERM=xterm",
}

var execCommand = cli.Command{
	Name:   "exec",
	Usage:  "execute a new command inside a container",
	Action: execAction,
	Flags: []cli.Flag{
		cli.BoolFlag{"tty", "allocate a tty to the container"},
		cli.StringSliceFlag{"env", &defaultEnv, "environment variables"},
	},
}

func execAction(context *cli.Context) {
	var (
		exitCode int
		master   *os.File
		sigc     = make(chan os.Signal, 10)
		factory  = libcontainer.New([]string{os.Args[0], "init", "--fd", "3", "--"})
	)

	signal.Notify(sigc)

	config, err := loadContainer()
	if err != nil {
		log.Fatal(err)
	}

	process := &libcontainer.Process{
		Args:   context.Args(),
		Env:    context.StringSlice("env"),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	if context.Bool("tty") {
		if master, err = process.AllocatePty(); err != nil {
			log.Fatalf("failed to allocate pty: %s", err)
		}

		go io.Copy(master, os.Stdin)
		go io.Copy(os.Stdout, master)

		state, err := term.SetRawTerminal(os.Stdin.Fd())
		if err != nil {
			log.Fatal(err)
		}

		defer term.RestoreTerminal(os.Stdin.Fd(), state)
	}

	_, err = factory.Create(config, process)
	if err != nil {
		log.Fatalf("failed to exec: %s", err)
	}

	go func() {
		resizeTty(master)

		for sig := range sigc {
			switch sig {
			case syscall.SIGWINCH:
				resizeTty(master)
			default:
				process.Signal(sig)
			}
		}
	}()

	exitCode = process.Wait()

	os.Exit(exitCode)
}

func resizeTty(master *os.File) {
	if master == nil {
		return
	}

	ws, err := term.GetWinsize(os.Stdin.Fd())
	if err != nil {
		return
	}

	if err := term.SetWinsize(master.Fd(), ws); err != nil {
		return
	}
}
