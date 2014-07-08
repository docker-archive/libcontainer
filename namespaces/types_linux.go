package namespaces

import (
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"syscall"
)

var (
	OverFlowUid uint32
	OverFlowGid uint32
)

func setupOverFlowUidGid() error {
	var err error
	overflowuidstr, err := ioutil.ReadFile("/proc/sys/kernel/overflowuid")
	if err != nil {
		return err
	}
	overflowgidstr, err := ioutil.ReadFile("/proc/sys/kernel/overflowgid")
	if err != nil {
		return err
	}

	overFlowUid64, err := strconv.ParseUint(strings.TrimSpace(string(overflowuidstr)), 10, 32)
	if err != nil {
		return err
	}
	OverFlowUid = uint32(overFlowUid64)

	overFlowGid64, err := strconv.ParseUint(strings.TrimSpace(string(overflowgidstr)), 10, 32)
	if err != nil {
		return err
	}
	OverFlowGid = uint32(overFlowGid64)

	return nil
}

func init() {
	namespaceList = Namespaces{
		{Key: "NEWNS", Value: syscall.CLONE_NEWNS, File: "mnt"},
		{Key: "NEWUTS", Value: syscall.CLONE_NEWUTS, File: "uts"},
		{Key: "NEWIPC", Value: syscall.CLONE_NEWIPC, File: "ipc"},
		{Key: "NEWUSER", Value: syscall.CLONE_NEWUSER, File: "user"},
		{Key: "NEWPID", Value: syscall.CLONE_NEWPID, File: "pid"},
		{Key: "NEWNET", Value: syscall.CLONE_NEWNET, File: "net"},
	}

	if err := setupOverFlowUidGid(); err != nil {
		log.Fatalf("Failed to read overflowuid/overflowgid: %v")
	}
}
