/* A part of this code was copied from the golang sources src/os/exec/exec.go */

package libct

// #cgo CFLAGS: -DCONFIG_X86_64 -DARCH="x86" -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
// #include "../src/include/uapi/libct.h"
// #include "../src/include/uapi/libct-errors.h"
// #include <stdlib.h>
import "C"
import "os"
import "io"
import "syscall"
import "unsafe"

type ProcessDesc struct {
	desc   C.ct_process_desc_t
	handle C.ct_process_t

	// Stdin specifies the process's standard input. If Stdin is
	// nil, the process reads from the null device (os.DevNull).
	Stdin io.Reader

	// Stdout and Stderr specify the process's standard output and error.
	//
	// If either is nil, Run connects the corresponding file descriptor
	// to the null device (os.DevNull).
	//
	// If Stdout and Stderr are the same writer, at most one
	// goroutine at a time will call Write.
	Stdout io.Writer
	Stderr io.Writer

	// ExtraFiles specifies additional open files to be inherited by the
	// new process. It does not include standard input, standard output, or
	// standard error. If non-nil, entry i becomes file descriptor 3+i.
	ExtraFiles []file

	childFiles      []file
	closeAfterStart []io.Closer
	closeAfterWait  []io.Closer
	goroutine       []func() error

	errch chan error // one send per goroutine
}

// interfaceEqual protects against panics from doing equality tests on
// two interfaces with non-comparable underlying types.
func interfaceEqual(a, b interface{}) bool {
	defer func() {
		recover()
	}()
	return a == b
}

func (p *ProcessDesc) writerDescriptor(w io.Writer) (f *os.File, err error) {
	if w == nil {
		f, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		p.closeAfterStart = append(p.closeAfterStart, f)
		return
	}

	if f, ok := w.(*os.File); ok {
		return f, nil
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return
	}

	p.closeAfterStart = append(p.closeAfterStart, pw)
	p.closeAfterWait = append(p.closeAfterWait, pr)
	p.goroutine = append(p.goroutine, func() error {
		_, err := io.Copy(w, pr)
		return err
	})
	return pw, nil
}

func (p *ProcessDesc) stdout() (f file, err error) {
	if f, ok := p.Stdout.(console); ok {
		return f, nil
	}
	return p.writerDescriptor(p.Stdout)
}

func (p *ProcessDesc) stderr() (f file, err error) {
	if f, ok := p.Stderr.(console); ok {
		return f, nil
	}
	if p.Stderr != nil && interfaceEqual(p.Stderr, p.Stdout) {
		return p.childFiles[1], nil
	}
	return p.writerDescriptor(p.Stderr)
}

func (c *ProcessDesc) stdin() (f file, err error) {
	if c.Stdin == nil {
		f, err = os.Open(os.DevNull)
		if err != nil {
			return
		}
		c.closeAfterStart = append(c.closeAfterStart, f)
		return
	}

	if f, ok := c.Stdin.(console); ok {
		return f, nil
	}
	if f, ok := c.Stdin.(*os.File); ok {
		return f, nil
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return
	}

	c.closeAfterStart = append(c.closeAfterStart, pr)
	c.closeAfterWait = append(c.closeAfterWait, pw)
	c.goroutine = append(c.goroutine, func() error {
		_, err := io.Copy(pw, c.Stdin)
		if err1 := pw.Close(); err == nil {
			err = err1
		}
		return err
	})
	return pr, nil
}

func (p *ProcessDesc) closeDescriptors(closers []io.Closer) {
	for _, fd := range closers {
		fd.Close()
	}
}

func (p *ProcessDesc) SetCaps(mask uint64, apply_to int) error {
	ret := C.libct_process_desc_set_caps(p.desc, C.ulong(mask), C.uint(apply_to))
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) SetUid(uid int) error {
	ret := C.libct_process_desc_setuid(p.desc, C.uint(uid))
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) SetGid(gid int) error {
	ret := C.libct_process_desc_setgid(p.desc, C.uint(gid))
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) SetUser(user string) error {
	cuser := C.CString(user)
	defer C.free(unsafe.Pointer(cuser))
	ret := C.libct_process_desc_set_user(p.desc, cuser)
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) SetParentDeathSignal(sig syscall.Signal) error {
	if ret := C.libct_process_desc_set_pdeathsig(p.desc, C.int(sig)); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) SetLSMLabel(label string) error {
	clabel := C.CString(label)
	defer C.free(unsafe.Pointer(clabel))

	if ret := C.libct_process_desc_set_lsm_label(p.desc, clabel); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) Wait() (*os.ProcessState, error) {

	pid, err := p.GetPid()
	if err != nil {
		return nil, err
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	ps, err := process.Wait()
	if err != nil {
		return nil, err
	}

	var copyError error
	for _ = range p.goroutine {
		if err := <-p.errch; err != nil && copyError == nil {
			copyError = err
		}
	}

	p.closeDescriptors(p.closeAfterWait)

	return ps, nil
}

func (p *ProcessDesc) SetEnv(env []string) error {
	cenv := make([]*C.char, len(env))
	for i, v := range env {
		cenv[i] = C.CString(v)
	}

	ret := C.libct_process_desc_set_env(p.desc, &cenv[0], C.int(len(env)))

	for i := range cenv {
		C.free(unsafe.Pointer(cenv[i]))
	}
	if ret < 0 {
		return LibctError{int(ret)}
	}
	return nil
}

func (p *ProcessDesc) SetRlimit(resource int, soft uint64, hard uint64) error {
	ret := C.libct_process_desc_set_rlimit(p.desc, C.int(resource), C.uint64_t(soft), C.uint64_t(hard))
	if ret < 0 {
		return LibctError{int(ret)}
	}
	return nil
}

func (p *ProcessDesc) GetPid() (int, error) {

	ret := C.libct_process_get_pid(p.handle)
	if ret < 0 {
		return -1, LibctError{int(ret)}
	}

	return int(ret), nil
}
