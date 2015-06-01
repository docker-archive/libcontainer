package nsenter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type pid struct {
	Pid int `json:"Pid"`
}

func TestNsenterValidPaths(t *testing.T) {
	args := []string{"nsenter-exec"}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe %v", err)
	}

	namespaces := []string{
		// join pid ns of the current process
		fmt.Sprintf("/proc/%d/ns/pid", os.Getpid()),
	}
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{w},
		Env: []string{
			fmt.Sprintf("_LIBCONTAINER_NSPATH=%s", strings.Join(namespaces, ",")),
			// the process needs to be cloned to join pidns properly
			"_LIBCONTAINER_DOCLONE=true",
			"_LIBCONTAINER_INITPIPE=3",
		},
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start %v", err)
	}
	w.Close()

	decoder := json.NewDecoder(r)
	var pid *pid

	if err := decoder.Decode(&pid); err != nil {
		dir, _ := ioutil.ReadDir(fmt.Sprintf("/proc/%d/ns", os.Getpid()))
		for _, d := range dir {
			t.Log(d.Name())
		}
		t.Fatalf("%v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter exits with a non-zero exit status")
	}
	p, err := os.FindProcess(pid.Pid)
	if err != nil {
		t.Fatalf("%v", err)
	}
	p.Wait()
}

func TestNsenterInvalidPaths(t *testing.T) {
	args := []string{"nsenter-exec"}
	_, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe %v", err)
	}

	namespaces := []string{
		// join pid ns of the current process
		fmt.Sprintf("/proc/%d/ns/pid", -1),
	}
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{w},
		Env: []string{
			// join an invalid namespace
			fmt.Sprintf("_LIBCONTAINER_NSPATH=%s", strings.Join(namespaces, ",")),
			// the process needs to be cloned to join pidns properly
			"_LIBCONTAINER_DOCLONE=true",
			"_LIBCONTAINER_INITPIPE=3",
		},
	}

	if err := cmd.Run(); err == nil {
		t.Fatal("nsenter exits with a zero exit status")
	}
}

func init() {
	if strings.HasPrefix(os.Args[0], "nsenter-") {
		os.Exit(0)
	}
	return
}
