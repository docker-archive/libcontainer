// +build seccomp,linux,cgo

package seccomp

import (
	"strings"
	"testing"

	"sourceforge.net/seccomp"
)

func TestInitSeccomp(t *testing.T) {
	var seccomps []Seccomps
	RestrictSyscalls := []string{"kexec_load", "open_by_handle_at", "init_module", "finit_module", "delete_module", "iopl", "ioperm", "swapon", "swapoff", "sysfs", "sysctl", "adjtimex", "clock_adjtime", "lookup_dcookie", "perf_event_open", "fanotify_init", "kcmp"}
	for s := range RestrictSyscalls {
		seccomps = append(seccomps, Seccomp{Syscall: s})
	}
	if err := InitSeccomp(nil); err != nil {
		t.Log("InitLabels Failed")
		t.Fatal(err)
	}

	if err := InitSeccomp(seccomps); err != nil {
		t.Log("InitLabels Failed")
		t.Fatal(err)
	}
}
