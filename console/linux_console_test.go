package console

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDupSTD(t *testing.T) {
	fds := make(map[int]int)
	// setup test mocks
	dup2 = func(from, to int) error {
		fds[to] = from
		return nil
	}
	open = func(name string, mode int, perm uint32) (int, error) {
		return 10, nil
	}

	c := &linuxConsole{
		path: "testpath",
	}
	if err := c.Dup(); err != nil {
		t.Fatal(err)
	}

	// ensure that FDs 0, 1, 2 were duped
	for _, i := range []int{0, 1, 2} {
		if fds[i] != 10 {
			t.Fatalf("fd %d was not successfully dup2 to 10")
		}
	}
}

func TestBindConsole(t *testing.T) {
	var (
		expectedPath = "/dev/myconsole"
		rootfs       = "/myroot"

		chmodCalled, chownCalled, createCalled, mountCalled bool
	)
	umask = func(in int) int {
		return in
	}
	chmod = func(path string, perm os.FileMode) error {
		if path != expectedPath {
			t.Fatalf("expected path %q but received %q", expectedPath, path)
		}
		if perm != 0600 {
			t.Fatalf("expected perm %d but received %d", 0600, perm)
		}
		chmodCalled = true
		return nil
	}
	chown = func(path string, uid, gid int) error {
		if path != expectedPath {
			t.Fatalf("expected path %q but received %q", expectedPath, path)
		}
		if uid != 0 {
			t.Fatalf("expected uid %d but received %d", 0, uid)
		}
		if gid != 0 {
			t.Fatalf("expected gid %d but received %d", 0, gid)
		}
		chownCalled = true
		return nil
	}
	create = func(path string) (*os.File, error) {
		expected := filepath.Join(rootfs, "dev/console")
		if path != expected {
			t.Fatalf("expected to create path %q but received %q", expected, path)
		}
		createCalled = true
		return nil, syscall.EEXIST
	}
	mount = func(source, dest, tpe string, flags uintptr, data string) error {
		if source != expectedPath {
			t.Fatalf("expected source %q but recevied %q", expectedPath, source)
		}
		expected := filepath.Join(rootfs, "dev/console")
		if expected != dest {
			t.Fatalf("expected dest %q but recevied %q", expected, dest)
		}
		if tpe != "bind" {
			t.Fatalf("expected type %q but received %q", "bind", tpe)
		}
		if flags != syscall.MS_BIND {
			t.Fatalf("expected mount flag %d but received %d", syscall.MS_BIND, flags)
		}
		mountCalled = true
		return nil
	}
	c := &linuxConsole{
		path: expectedPath,
	}
	if err := c.Bind(rootfs, ""); err != nil {
		t.Fatal(err)
	}

	if !createCalled {
		t.Fatal("expected create to be called")
	}
	if !chmodCalled {
		t.Fatal("expected chmod to be called")
	}
	if !chownCalled {
		t.Fatal("expected chown to be called")
	}
	if !mountCalled {
		t.Fatal("expected mount to be called")
	}
}

func TestNew(t *testing.T) {
	var (
		myPath = "/myptsname"
	)
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		return nil, nil
	}
	unlockpt = func(_ *os.File) error {
		return nil
	}
	ptsname = func(_ *os.File) (string, error) {
		return myPath, nil
	}

	console, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if console == nil {
		t.Fatal("expected console to not be nil")
	}
	if console.Path() != myPath {
		t.Fatalf("expected path %q but received %q", myPath, console.Path())
	}
}

func TestGetNullConsole(t *testing.T) {
	console := FromPath("")
	if console == nil {
		t.Fatal("expected non nil console")
	}
	if _, ok := console.(*nullConsole); !ok {
		t.Fatal("expected console to be of type *nullConsole when path is empty")
	}
}

func TestGetLinuxConsole(t *testing.T) {
	console := FromPath("/something")
	if console == nil {
		t.Fatal("expected non nil console")
	}
	if _, ok := console.(*linuxConsole); !ok {
		t.Fatal("expected console to be of type *linuxConsole when path is empty")
	}

}
