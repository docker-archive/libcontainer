// +build !linux !cgo !seccomp

package seccomp

type Seccomp struct {
	Architecture string
	Syscall      string
	Args         []string
}

func InitSeccomp(secomps []Seccomp) error {
	return nil
}
