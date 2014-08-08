package main

import (
	"os"
	. "syscall"

	"github.com/docker/libcontainer/forkexec"
)

func main() {
	uidMappings := []forkexec.IdMap{
		{
			ContainerId: 0,
			HostId:      1000,
			Size:        1,
		},
	}

	gidMappings := []forkexec.IdMap{
		{
			ContainerId: 0,
			HostId:      1000,
			Size:        1,
		},
	}

	pid, err := forkexec.ForkExecNew("/bin/sh", []string{"sh"}, &ProcAttr{
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys: &SysProcAttr{
			Cloneflags: CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS,
			Credential: &Credential{Uid: 0, Gid: 0},
		},
	}, uidMappings, gidMappings)
	if err != nil {
		panic(err)
	}

	var wstatus WaitStatus
	_, err1 := Wait4(pid, &wstatus, 0, nil)
	if err != nil {
		panic(err1)
	}
}
