package libct

import "testing"
import "syscall"
import "os"

func init() {
	LogInit(os.Stderr, LOG_MSG)
}

func TestSpawnExecv(t *testing.T) {
	s := &Session{}

	err := s.OpenLocal()
	if err != nil {
		t.Fatal(err)
	}

	p, err := s.ProcessCreateDesc()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := s.ContainerCreate("test")
	if err != nil {
		t.Fatal(err)
	}

	preCmds := []Command{
		{Path: "touch", Args: []string{"touch", "/tmp/hello"}},
		{Path: "touch", Args: []string{"touch", "/tmp/hello2"}},
	}
	postCmds := []Command{
		{Path: "touch", Args: []string{"touch", "/tmp/Hello"}},
		{Path: "touch", Args: []string{"touch", "/tmp/Hello2"}},
	}
	ct.AddMount("", "/tmp", 0, "tmpfs", "", preCmds, postCmds)

	ct.SetNsMask(syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	if err = p.SetEnv([]string{"PATH=/bin:/usr/bin"}); err != nil {
		t.Fatal(err)
	}

	err = ct.SpawnExecve(p, "sh",
		[]string{"sh", "-c", "env | grep -q TEST_LIBCT=test_libct"},
		[]string{"TEST_LIBCT=test_libct"})
	if err != nil {
		t.Fatal(err)
	}
	status, err := p.Wait()
	ct.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Success() {
		t.Fatal(status.String())
	}
}

func TestSpawnExecvStdout(t *testing.T) {
	s := &Session{}

	err := s.OpenLocal()
	if err != nil {
		t.Fatal(err)
	}

	p, err := s.ProcessCreateDesc()
	if err != nil {
		t.Fatal(err)
	}

	pr, pw, err := os.Pipe()
	ir, iw, err := os.Pipe()
	er, ew, err := os.Pipe()
	tr, tw, err := os.Pipe()

	p.Stdout = pw
	p.Stdin = ir
	p.Stderr = ew
	p.ExtraFiles = append(p.ExtraFiles, tr)

	ct, err := s.ContainerCreate("test")
	if err != nil {
		t.Fatal(err)
	}

	if err = ct.AddController(CTL_CPU); err != nil {
		t.Fatal(err)
	}
	if err = ct.AddController(CTL_MEMORY); err != nil {
		t.Fatal(err)
	}
	if err = p.SetEnv([]string{"TEST_LIBCT=hello", "PATH=/bin:/usr/bin"}); err != nil {
		t.Fatal(err)
	}
	err = ct.SpawnExecve(p, "sh",
		[]string{"sh", "-c", "echo ok; cat; cat <&3 >&2; env | grep -q TEST_LIBCT"},
		nil)
	defer ct.Wait()

	val, err := ct.ReadController(CTL_MEMORY, "memory.usage_in_bytes")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(val)

	pw.Close()
	ir.Close()
	tr.Close()
	ew.Close()
	defer pr.Close()
	defer iw.Close()
	defer tw.Close()
	defer er.Close()

	if err != nil {
		t.Fatal(err)
	}

	procs, err := ct.Processes()
	if err != nil {
		t.Fatal(err)
	}

	if len(procs) > 2 {
		t.Fatal(procs)
	}

	iw.WriteString("iok")
	iw.Close()
	tw.WriteString("good")
	tw.Close()

	status, err := p.Wait()
	if err != nil {
		t.Fatal(status)
	}
	ct.Wait()

	data := make([]byte, 1024)
	count, err := er.Read(data)
	if count != 4 {
		t.Fatal(count, string(data), data)
	}
	count, err = pr.Read(data)
	if count != 6 {
		t.Fatal(count, string(data), data)
	}
	if !status.Success() {
		t.Fatal(status.String())
	}
}
