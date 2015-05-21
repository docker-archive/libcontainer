package libct

// #include <stdlib.h>
import "C"

import "unsafe"

func __allocCmd(c *Command, toFree [][]*C.char) (*C.struct_libct_cmd, [][]*C.char) {
	var cmd *C.struct_libct_cmd

	cmd = (*C.struct_libct_cmd)(C.malloc(C.size_t(unsafe.Sizeof(*cmd))))

	if len(c.Dir) != 0 {
		cmd.dir = C.CString(c.Dir)
	} else {
		cmd.dir = nil
	}
	cmd.path = C.CString(c.Path)
	cmd.next = nil

	cargv := make([]*C.char, len(c.Args)+1)
	toFree = append(toFree, cargv)

	for i, arg := range c.Args {
		cargv[i] = C.CString(arg)
	}
	cmd.argv = &cargv[0]

	var penv **C.char
	if c.Env == nil {
		penv = nil
	} else {
		cenv := make([]*C.char, len(c.Env)+1)
		toFree = append(toFree, cenv)

		for i, e := range c.Env {
			cenv[i] = C.CString(e)
		}
		penv = &cenv[0]
	}
	cmd.envp = penv

	return cmd, toFree
}

func allocCmd(cmds []Command) (*C.struct_libct_cmd, [][]*C.char) {
	var start, prev *C.struct_libct_cmd
	var toFree [][]*C.char

	start = nil
	for i := range cmds {
		var cmd *C.struct_libct_cmd
		c := &cmds[i]
		cmd, toFree = __allocCmd(c, toFree)

		if start == nil {
			start = cmd
		} else {
			prev.next = cmd
		}
		prev = cmd
	}

	return start, toFree
}

func freeCmd(cmd *C.struct_libct_cmd, toFree [][]*C.char) {
	freeStrings := func(array []*C.char) {
		for _, item := range array {
			if item != nil {
				C.free(unsafe.Pointer(item))
			}
		}
	}

	for _, f := range toFree {
		freeStrings(f)
	}

	for cmd != nil {
		next := cmd.next

		defer C.free(unsafe.Pointer(cmd.dir))
		defer C.free(unsafe.Pointer(cmd.path))
		defer C.free(unsafe.Pointer(cmd))

		cmd = next
	}
}
