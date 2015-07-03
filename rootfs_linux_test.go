// +build linux

package libcontainer

import "testing"

func TestCheckMountDestOnProc(t *testing.T) {
	dest := "/rootfs/proc/"
	err := checkMountDest("/rootfs", dest)
	if err == nil {
		t.Fatal("destination inside proc should return an error")
	}
}

func TestCheckMountDestInSys(t *testing.T) {
	dest := "/rootfs/sys/fs"
	err := checkMountDest("/rootfs", dest)
	if err == nil {
		t.Fatal("destination inside sys should return an error")
	}
}

func TestCheckMountDestFalsePositive(t *testing.T) {
	dest := "/rootfs/sysfiles/fs/cgroup"
	err := checkMountDest("/rootfs", dest)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckMountRoot(t *testing.T) {
	dest := "/rootfs"
	err := checkMountDest("/rootfs", dest)
	if err == nil {
		t.Fatal(err)
	}
}

func TestCheckMountDestException(t *testing.T) {
	dest := "/rootfs/sys/fs/cgroup"
	err := checkMountDest("/rootfs", dest)
	if err != nil {
		t.Fatal("/sys/fs/cgroup is an exception, should not fail")
	}
}
