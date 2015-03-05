package libct

// #cgo CFLAGS: -DCONFIG_X86_64 -DARCH="x86" -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
// #include <stdlib.h>
// #include "../src/include/uapi/libct.h"
// #include "../src/include/uapi/libct-errors.h"
// #include "../src/include/uapi/libct-log-levels.h"
import "C"

import "os"
import "fmt"
import "unsafe"

const (
	LIBCT_OPT_AUTO_PROC_MOUNT = C.LIBCT_OPT_AUTO_PROC_MOUNT
	LIBCT_OPT_SYSTEMD         = C.LIBCT_OPT_SYSTEMD

	CAPS_BSET    = C.CAPS_BSET
	CAPS_ALLCAPS = C.CAPS_ALLCAPS
	CAPS_ALL     = C.CAPS_ALL

	CT_ERROR   = C.CT_ERROR
	CT_STOPPED = C.CT_STOPPED
	CT_RUNNING = C.CT_RUNNING
	CT_PAUSED  = C.CT_PAUSED
)

type file interface {
	Fd() uintptr
	Close() error
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
}

type console struct {
}

var Console console

func (c console) Fd() uintptr {
	return ^uintptr(0)
}

func (c console) Close() error {
	return nil
}

func (c console) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (c console) Write(p []byte) (n int, err error) {
	return 0, nil
}

type Session struct {
	s C.libct_session_t
}

type Container struct {
	ct C.ct_handler_t
}

type NetDev struct {
	dev C.ct_net_t
}

type NetRoute struct {
	route C.ct_net_route_t
}

type NetRouteNextHop struct {
	nh C.ct_net_route_nh_t
}

type LibctError struct {
	Code int
}

func (e LibctError) Error() string {
	return fmt.Sprintf("LibctError: %x", e.Code)
}

func (s *Session) OpenLocal() error {
	h := C.libct_session_open_local()

	if C.libct_handle_is_err(unsafe.Pointer(h)) != 0 {
		return LibctError{int(C.libct_handle_to_err(unsafe.Pointer(h)))}
	}

	s.s = h

	return nil
}

func (s *Session) ContainerCreate(name string) (*Container, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	ct := C.libct_container_create(s.s, cname)

	if C.libct_handle_is_err(unsafe.Pointer(ct)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(ct)))}
	}

	return &Container{ct}, nil
}

func (s *Session) ContainerOpen(name string) (*Container, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	ct := C.libct_container_open(s.s, cname)

	if C.libct_handle_is_err(unsafe.Pointer(ct)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(ct)))}
	}

	return &Container{ct}, nil
}

func (s *Session) ProcessCreateDesc() (*ProcessDesc, error) {
	p := C.libct_process_desc_create(s.s)
	if C.libct_handle_is_err(unsafe.Pointer(p)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(p)))}
	}

	return &ProcessDesc{desc: p}, nil
}

func (ct *Container) SetNsMask(nsmask uint64) error {
	ret := C.libct_container_set_nsmask(ct.ct, C.ulong(nsmask))

	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) SetNsPath(ns int, path string) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	ret := C.libct_container_set_nspath(ct.ct, C.int(ns), cpath)
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) SetSysctl(name string, val string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	cval := C.CString(val)
	defer C.free(unsafe.Pointer(cval))

	ret := C.libct_container_set_sysctl(ct.ct, cname, cval)
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) Kill() error {
	ret := C.libct_container_kill(ct.ct)

	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) State() (int, error) {
	ret := C.libct_container_state(ct.ct)

	if ret < 0 {
		return CT_ERROR, LibctError{int(ret)}
	}

	return int(ret), nil
}

func (ct *Container) Pause() error {
	ret := C.libct_container_pause(ct.ct)

	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) Resume() error {
	ret := C.libct_container_resume(ct.ct)

	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func getFd(f file) C.int {
	if _, ok := f.(console); ok {
		return C.LIBCT_CONSOLE_FD
	}

	return C.int(f.Fd())
}

func (ct *Container) SetConsoleFd(f file) error {
	ret := C.libct_container_set_console_fd(ct.ct, getFd(f))

	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) Load(p *ProcessDesc, pid int) error {
	h := C.libct_container_load(ct.ct, C.pid_t(pid))

	if C.libct_handle_is_err(unsafe.Pointer(h)) != 0 {
		p.closeDescriptors(p.closeAfterStart)
		p.closeDescriptors(p.closeAfterWait)
		return LibctError{int(C.libct_handle_to_err(unsafe.Pointer(h)))}
	}

	p.handle = h

	return nil
}

func (ct *Container) SpawnExecve(p *ProcessDesc, path string, argv []string, env []string) error {
	err := ct.execve(p, path, argv, env, true)

	return err
}

func (ct *Container) EnterExecve(p *ProcessDesc, path string, argv []string, env []string) error {
	err := ct.execve(p, path, argv, env, false)
	return err
}

func (ct *Container) execve(p *ProcessDesc, path string, argv []string, env []string, spawn bool) error {
	var (
		h C.ct_process_t
		i int = 0
	)

	type F func(*ProcessDesc) (file, error)
	for _, setupFd := range []F{(*ProcessDesc).stdin, (*ProcessDesc).stdout, (*ProcessDesc).stderr} {
		fd, err := setupFd(p)
		if err != nil {
			p.closeDescriptors(p.closeAfterStart)
			p.closeDescriptors(p.closeAfterWait)
			return err
		}
		p.childFiles = append(p.childFiles, fd)
		i = i + 1
	}

	freeStrings := func(array []*C.char) {
		for _, item := range array {
			if item != nil {
				C.free(unsafe.Pointer(item))
			}
		}
	}

	p.childFiles = append(p.childFiles, p.ExtraFiles...)

	cargv := make([]*C.char, len(argv)+1)
	defer freeStrings(cargv)

	for i, arg := range argv {
		cargv[i] = C.CString(arg)
	}

	var penv **C.char
	if env == nil {
		penv = nil
	} else {
		cenv := make([]*C.char, len(env)+1)
		defer freeStrings(cenv)

		for i, e := range env {
			cenv[i] = C.CString(e)
		}
		penv = &cenv[0]
	}

	cfds := make([]C.int, len(p.childFiles))
	for i, fd := range p.childFiles {
		cfds[i] = C.int(getFd(fd))
	}

	C.libct_process_desc_set_fds(p.desc, &cfds[0], C.int(len(p.childFiles)))

	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	if spawn {
		h = C.libct_container_spawn_execve(ct.ct, p.desc, cpath, &cargv[0], penv)
	} else {
		h = C.libct_container_enter_execve(ct.ct, p.desc, cpath, &cargv[0], penv)
	}

	if C.libct_handle_is_err(unsafe.Pointer(h)) != 0 {
		p.closeDescriptors(p.closeAfterStart)
		p.closeDescriptors(p.closeAfterWait)
		return LibctError{int(C.libct_handle_to_err(unsafe.Pointer(h)))}
	}

	p.closeDescriptors(p.closeAfterStart)

	p.errch = make(chan error, len(p.goroutine))
	for _, fn := range p.goroutine {
		go func(fn func() error) {
			p.errch <- fn()
		}(fn)
	}

	p.handle = h

	return nil
}

func (ct *Container) Wait() error {
	ret := C.libct_container_wait(ct.ct)

	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) Destroy() error {
	C.libct_container_destroy(ct.ct)

	ct.ct = nil

	return nil
}

func (ct *Container) Uname(host *string, domain *string) error {
	var chost *C.char
	var cdomain *C.char

	if host != nil {
		chost = C.CString(*host)
		defer C.free(unsafe.Pointer(chost))
	}

	if domain != nil {
		cdomain = C.CString(*domain)
		defer C.free(unsafe.Pointer(cdomain))
	}

	ret := C.libct_container_uname(ct.ct, chost, cdomain)

	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) SetRoot(root string) error {
	croot := C.CString(root)
	defer C.free(unsafe.Pointer(croot))

	if ret := C.libct_fs_set_root(ct.ct, croot); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

const (
	CT_FS_RDONLY      = C.CT_FS_RDONLY
	CT_FS_PRIVATE     = C.CT_FS_PRIVATE
	CT_FS_NOEXEC      = C.CT_FS_NOEXEC
	CT_FS_NOSUID      = C.CT_FS_NOSUID
	CT_FS_NODEV       = C.CT_FS_NODEV
	CT_FS_STRICTATIME = C.CT_FS_STRICTATIME
	CT_FS_REC         = C.CT_FS_REC
	CT_FS_BIND        = C.CT_FS_BIND
)

func (ct *Container) AddUidMap(first, lower_first, count int) error {
	ret := C.libct_userns_add_uid_map(ct.ct, C.uint(first), C.uint(lower_first), C.uint(count))
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) AddGidMap(first, lower_first, count int) error {
	ret := C.libct_userns_add_gid_map(ct.ct, C.uint(first), C.uint(lower_first), C.uint(count))
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) AddBindMount(src string, dst string, flags int) error {
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))

	cdst := C.CString(dst)
	defer C.free(unsafe.Pointer(cdst))

	if ret := C.libct_fs_add_bind_mount(ct.ct, csrc, cdst, C.int(flags)); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

type Command struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
	Env  []string `json:"env"`
	Dir  string   `json:"dir"`
}

func (ct *Container) AddMount(src string, dst string, flags int, fstype string, data string, preCmds []Command, postCmds []Command) error {
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))

	cdst := C.CString(dst)
	defer C.free(unsafe.Pointer(cdst))

	cfstype := C.CString(fstype)
	defer C.free(unsafe.Pointer(cfstype))

	cdata := C.CString(data)
	defer C.free(unsafe.Pointer(cdata))

	pre, preFree := allocCmd(preCmds)
	defer freeCmd(pre, preFree)
	post, postFree := allocCmd(postCmds)
	defer freeCmd(post, postFree)

	if ret := C.libct_fs_add_mount_with_actions(ct.ct, csrc, cdst, C.int(flags), cfstype, cdata, pre, post); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

const (
	CTL_BLKIO   = C.CTL_BLKIO
	CTL_CPU     = C.CTL_CPU
	CTL_CPUACCT = C.CTL_CPUACCT
	CTL_CPUSET  = C.CTL_CPUSET
	CTL_DEVICES = C.CTL_DEVICES
	CTL_FREEZER = C.CTL_FREEZER
	CTL_HUGETLB = C.CTL_HUGETLB
	CTL_MEMORY  = C.CTL_MEMORY
	CTL_NETCLS  = C.CTL_NETCLS
)

func (ct *Container) AddController(ctype int) error {
	if ret := C.libct_controller_add(ct.ct, C.enum_ct_controller(ctype)); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) ConfigureController(ctype int, param string, value string) error {
	cparam := C.CString(param)
	defer C.free(unsafe.Pointer(cparam))
	cvalue := C.CString(value)
	defer C.free(unsafe.Pointer(cvalue))

	ret := C.libct_controller_configure(ct.ct, C.enum_ct_controller(ctype), cparam, cvalue)
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) ReadController(ctype int, param string) (string, error) {
	cparam := C.CString(param)
	defer C.free(unsafe.Pointer(cparam))

	buf := make([]byte, 4096)

	ret := C.libct_controller_read(ct.ct, C.enum_ct_controller(ctype), cparam, unsafe.Pointer(&buf[0]), 4096)
	if ret < 0 {
		return "", LibctError{int(ret)}
	}

	return string(buf[:ret]), nil
}

func (ct *Container) Processes() ([]int, error) {
	ctasks := C.libct_container_processes(ct.ct)
	if C.libct_handle_is_err(unsafe.Pointer(ctasks)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(ctasks)))}
	}
	defer C.libct_processes_free(ctasks)

	tasks := make([]int, int(ctasks.nproc))
	for i := 0; i < int(ctasks.nproc); i++ {
		tasks[i] = int(C.libct_processes_get(ctasks, C.int(i)))
	}

	return tasks, nil
}

func (ct *Container) SetOption(opt int32) error {
	if ret := C.libct_container_set_option(ct.ct, C.int(opt), nil); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (ct *Container) AddDeviceNode(path string, mode int, major int, minor int) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	ret := C.libct_fs_add_devnode(ct.ct, cpath, C.int(mode), C.int(major), C.int(minor))
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (nd *NetDev) GetPeer() (*NetDev, error) {

	dev := C.libct_net_dev_get_peer(nd.dev)

	if C.libct_handle_is_err(unsafe.Pointer(dev)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(dev)))}
	}

	return &NetDev{dev}, nil
}

func (ct *Container) AddNetVeth(host_name string, ct_name string) (*NetDev, error) {

	var args C.struct_ct_net_veth_arg

	chost_name := C.CString(host_name)
	defer C.free(unsafe.Pointer(chost_name))
	cct_name := C.CString(ct_name)
	defer C.free(unsafe.Pointer(cct_name))

	args.host_name = chost_name
	args.ct_name = cct_name

	dev := C.libct_net_add(ct.ct, C.CT_NET_VETH, unsafe.Pointer(&args))

	if C.libct_handle_is_err(unsafe.Pointer(dev)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(dev)))}
	}

	return &NetDev{dev}, nil
}

func (dev *NetDev) AddIpAddr(addr string) error {
	caddr := C.CString(addr)
	defer C.free(unsafe.Pointer(caddr))

	err := C.libct_net_dev_add_ip_addr(dev.dev, caddr)
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

func (dev *NetDev) SetMaster(master string) error {
	cmaster := C.CString(master)
	defer C.free(unsafe.Pointer(cmaster))

	err := C.libct_net_dev_set_master(dev.dev, cmaster)
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

func (dev *NetDev) SetMtu(mtu int) error {
	err := C.libct_net_dev_set_mtu(dev.dev, C.int(mtu))
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

func (ct *Container) AddRoute() (*NetRoute, error) {
	r := C.libct_net_route_add(ct.ct)

	if C.libct_handle_is_err(unsafe.Pointer(r)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(r)))}
	}

	return &NetRoute{r}, nil
}

func (route *NetRoute) SetSrc(src string) error {
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))

	err := C.libct_net_route_set_src(route.route, csrc)
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

func (route *NetRoute) SetDst(dst string) error {
	cdst := C.CString(dst)
	defer C.free(unsafe.Pointer(cdst))

	err := C.libct_net_route_set_dst(route.route, cdst)
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

func (route *NetRoute) SetDev(dev string) error {
	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	err := C.libct_net_route_set_dev(route.route, cdev)
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

func (route *NetRoute) AddNextHop() (*NetRouteNextHop, error) {
	nh := C.libct_net_route_add_nh(route.route)
	if C.libct_handle_is_err(unsafe.Pointer(nh)) != 0 {
		return nil, LibctError{int(C.libct_handle_to_err(unsafe.Pointer(nh)))}
	}

	return &NetRouteNextHop{nh}, nil
}

func (nh *NetRouteNextHop) SetGateway(addr string) error {
	caddr := C.CString(addr)
	defer C.free(unsafe.Pointer(caddr))

	err := C.libct_net_route_nh_set_gw(nh.nh, caddr)
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

func (nh *NetRouteNextHop) SetDev(dev string) error {
	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	err := C.libct_net_route_nh_set_dev(nh.nh, cdev)
	if err != 0 {
		return LibctError{int(err)}
	}

	return nil
}

const (
	LOG_MSG   = C.LOG_MSG
	LOG_ERROR = C.LOG_ERROR
	LOG_WARN  = C.LOG_WARN
	LOG_INFO  = C.LOG_INFO
	LOG_DEBUG = C.LOG_DEBUG
)

func LogInit(fd *os.File, level uint) {
	C.libct_log_init(C.int(fd.Fd()), C.uint(level))
}
