package forkexec

import (
	"fmt"
	"io/ioutil"
	"strings"
	. "syscall"
	"unsafe"
)

// These functions are defined in forkexec.c
func BeforeFork()
func AfterFork()

var zeroProcAttr ProcAttr
var zeroSysProcAttr SysProcAttr

// This is similar to the standard go library implementation of forkExec with the addition
// of capability to write UID/GID mappings for user namespaces.
func ForkExecNew(argv0 string, argv []string, attr *ProcAttr, uidMappings, gidMappings []IdMap) (pid int, err error) {
	var p [2]int
	var n int
	var err1 Errno
	var wstatus WaitStatus

	if attr == nil {
		attr = &zeroProcAttr
	}
	sys := attr.Sys
	if sys == nil {
		sys = &zeroSysProcAttr
	}

	p[0] = -1
	p[1] = -1

	// Convert args to C form.
	argv0p, err := BytePtrFromString(argv0)
	if err != nil {
		return 0, err
	}
	argvp, err := SlicePtrFromStrings(argv)
	if err != nil {
		return 0, err
	}
	envvp, err := SlicePtrFromStrings(attr.Env)
	if err != nil {
		return 0, err
	}

	var chroot *byte
	if sys.Chroot != "" {
		chroot, err = BytePtrFromString(sys.Chroot)
		if err != nil {
			return 0, err
		}
	}
	var dir *byte
	if attr.Dir != "" {
		dir, err = BytePtrFromString(attr.Dir)
		if err != nil {
			return 0, err
		}
	}

	// Acquire the fork lock so that no other threads
	// create new fds that are not yet close-on-exec
	// before we fork.
	ForkLock.Lock()

	// Allocate child status pipe close on exec.
	if err = forkExecPipe(p[:]); err != nil {
		goto error
	}

	// Kick off child.
	pid, err1 = forkAndExecInChild(argv0p, argvp, envvp, chroot, dir, attr, sys, p[1], p[0])
	if err1 != 0 {
		err = Errno(err1)
		goto error
	}
	ForkLock.Unlock()

	if err := writeUserMappings(pid, uidMappings, gidMappings); err != nil {
		return 0, err
	}
	// Read child error status from pipe.
	Close(p[1])

	n, err = Read(p[0], nil)
	Close(p[0])

	if err != nil || n != 0 {
		if n == int(unsafe.Sizeof(err1)) {
			err = Errno(err1)
		}
		if err == nil {
			err = EPIPE
		}

		// Child failed; wait for it to exit, to make sure
		// the zombies don't accumulate.
		_, err1 := Wait4(pid, &wstatus, 0, nil)
		for err1 == EINTR {
			_, err1 = Wait4(pid, &wstatus, 0, nil)
		}
		return 0, err
	}

	// Read got EOF, so pipe closed on exec, so exec succeeded.
	return pid, nil

error:
	if p[0] >= 0 {
		Close(p[0])
		Close(p[1])
	}
	ForkLock.Unlock()
	return 0, err
}

func forkAndExecInChild(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *ProcAttr, sys *SysProcAttr, child int, parent int) (pid int, err Errno) {
	// Declare all variables at top in case any
	// declarations require heap allocation (e.g., err1).
	var (
		r1     uintptr
		err1   Errno
		nextfd int
		i      int
		lzero  uintptr
	)

	// Guard against side effects of shuffling fds below.
	// Make sure that nextfd is beyond any currently open files so
	// that we can't run the risk of overwriting any of them.
	fd := make([]int, len(attr.Files))
	nextfd = len(attr.Files)
	for i, ufd := range attr.Files {
		if nextfd < int(ufd) {
			nextfd = int(ufd)
		}
		fd[i] = int(ufd)
	}
	nextfd++

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	BeforeFork()
	r1, _, err1 = RawSyscall6(SYS_CLONE, uintptr(SIGCHLD)|sys.Cloneflags, 0, 0, 0, 0, 0)
	if err1 != 0 {
		AfterFork()
		return 0, err1
	}

	if r1 != 0 {
		// parent; return PID
		AfterFork()
		return int(r1), 0
	}

	// Fork succeeded, now in child.
	if _, _, err1 = RawSyscall(SYS_CLOSE, uintptr(child), 0, 0); err != 0 {
		goto childerror
	}

	_, _, err1 = RawSyscall(SYS_READ, uintptr(parent), uintptr(unsafe.Pointer(&lzero)), uintptr(1))
	if err1 != 0 {
		goto childerror
	}

	// Parent death signal
	if sys.Pdeathsig != 0 {
		_, _, err1 = RawSyscall6(SYS_PRCTL, PR_SET_PDEATHSIG, uintptr(sys.Pdeathsig), 0, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}

		// Signal self if parent is already dead. This might cause a
		// duplicate signal in rare cases, but it won't matter when
		// using SIGKILL.
		r1, _, _ = RawSyscall(SYS_GETPPID, 0, 0, 0)
		if r1 == 1 {
			pid, _, _ := RawSyscall(SYS_GETPID, 0, 0, 0)
			_, _, err1 := RawSyscall(SYS_KILL, pid, uintptr(sys.Pdeathsig), 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// Enable tracing if requested.
	if sys.Ptrace {
		_, _, err1 = RawSyscall(SYS_PTRACE, uintptr(PTRACE_TRACEME), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Session ID
	if sys.Setsid {
		_, _, err1 = RawSyscall(SYS_SETSID, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Set process group
	if sys.Setpgid {
		_, _, err1 = RawSyscall(SYS_SETPGID, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Chroot
	if chroot != nil {
		_, _, err1 = RawSyscall(SYS_CHROOT, uintptr(unsafe.Pointer(chroot)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// User and groups
	if cred := sys.Credential; cred != nil {
		ngroups := uintptr(len(cred.Groups))
		var groups unsafe.Pointer
		if ngroups > 0 {
			groups = unsafe.Pointer(&cred.Groups[0])
		}
		_, _, err1 = RawSyscall(SYS_SETGROUPS, ngroups, uintptr(groups), 0)
		if err1 != 0 {
			goto childerror
		}
		_, _, err1 = RawSyscall(SYS_SETGID, uintptr(cred.Gid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
		_, _, err1 = RawSyscall(SYS_SETUID, uintptr(cred.Uid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Chdir
	if dir != nil {
		_, _, err1 = RawSyscall(SYS_CHDIR, uintptr(unsafe.Pointer(dir)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Pass 1: look for fd[i] < i and move those up above len(fd)
	// so that pass 2 won't stomp on an fd it needs later.
	if child < nextfd {
		_, _, err1 = RawSyscall(SYS_DUP2, uintptr(child), uintptr(nextfd), 0)
		if err1 != 0 {
			goto childerror
		}
		RawSyscall(SYS_FCNTL, uintptr(nextfd), F_SETFD, FD_CLOEXEC)
		child = nextfd
		nextfd++
	}
	for i = 0; i < len(fd); i++ {
		if fd[i] >= 0 && fd[i] < int(i) {
			_, _, err1 = RawSyscall(SYS_DUP2, uintptr(fd[i]), uintptr(nextfd), 0)
			if err1 != 0 {
				goto childerror
			}
			RawSyscall(SYS_FCNTL, uintptr(nextfd), F_SETFD, FD_CLOEXEC)
			fd[i] = nextfd
			nextfd++
			if nextfd == child { // don't stomp on pipe
				nextfd++
			}
		}
	}

	// Pass 2: dup fd[i] down onto i.
	for i = 0; i < len(fd); i++ {
		if fd[i] == -1 {
			RawSyscall(SYS_CLOSE, uintptr(i), 0, 0)
			continue
		}
		if fd[i] == int(i) {
			// dup2(i, i) won't clear close-on-exec flag on Linux,
			// probably not elsewhere either.
			_, _, err1 = RawSyscall(SYS_FCNTL, uintptr(fd[i]), F_SETFD, 0)
			if err1 != 0 {
				goto childerror
			}
			continue
		}
		// The new fd is created NOT close-on-exec,
		// which is exactly what we want.
		_, _, err1 = RawSyscall(SYS_DUP2, uintptr(fd[i]), uintptr(i), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// By convention, we don't close-on-exec the fds we are
	// started with, so if len(fd) < 3, close 0, 1, 2 as needed.
	// Programs that know they inherit fds >= 3 will need
	// to set them close-on-exec.
	for i = len(fd); i < 3; i++ {
		RawSyscall(SYS_CLOSE, uintptr(i), 0, 0)
	}

	// Detach fd 0 from tty
	if sys.Noctty {
		_, _, err1 = RawSyscall(SYS_IOCTL, 0, uintptr(TIOCNOTTY), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Set the controlling TTY to Ctty
	if sys.Setctty && sys.Ctty >= 0 {
		_, _, err1 = RawSyscall(SYS_IOCTL, uintptr(sys.Ctty), uintptr(TIOCSCTTY), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Time to exec.
	_, _, err1 = RawSyscall(SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envv[0])))

childerror:
	// send error code on pipe
	RawSyscall(SYS_WRITE, uintptr(child), uintptr(unsafe.Pointer(&err1)), unsafe.Sizeof(err1))
	for {
		RawSyscall(SYS_EXIT, 253, 0, 0)
	}
}

func fcntl(fd int, cmd int, arg int) (val int, err error) {
	r0, _, e1 := Syscall(SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(arg))
	val = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}

// Try to open a pipe with O_CLOEXEC set on both file descriptors.
func forkExecPipe(p []int) (err error) {
	err = Pipe2(p, O_CLOEXEC)
	// pipe2 was added in 2.6.27 and our minimum requirement is 2.6.23, so it
	// might not be implemented.
	if err == ENOSYS {
		if err = Pipe(p); err != nil {
			return
		}
		if _, err = fcntl(p[0], F_SETFD, FD_CLOEXEC); err != nil {
			return
		}
		_, err = fcntl(p[1], F_SETFD, FD_CLOEXEC)
	}
	return
}

// Write UID/GID mappings for a process.
func writeUserMappings(pid int, uidMappings, gidMappings []IdMap) error {
	if len(uidMappings) > 5 || len(gidMappings) > 5 {
		return fmt.Errorf("Only 5 uid/gid mappings are supported by the kernel")
	}

	uidMapStr := make([]string, len(uidMappings))
	for i, um := range uidMappings {
		uidMapStr[i] = fmt.Sprintf("%v %v %v", um.ContainerId, um.HostId, um.Size)
	}

	gidMapStr := make([]string, len(gidMappings))
	for i, gm := range gidMappings {
		gidMapStr[i] = fmt.Sprintf("%v %v %v", gm.ContainerId, gm.HostId, gm.Size)
	}

	uidMap := []byte(strings.Join(uidMapStr, "\n"))
	gidMap := []byte(strings.Join(gidMapStr, "\n"))

	uidMappingsFile := fmt.Sprintf("/proc/%v/uid_map", pid)
	gidMappingsFile := fmt.Sprintf("/proc/%v/gid_map", pid)

	if err := ioutil.WriteFile(uidMappingsFile, uidMap, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(gidMappingsFile, gidMap, 0644); err != nil {
		return err
	}

	return nil
}
