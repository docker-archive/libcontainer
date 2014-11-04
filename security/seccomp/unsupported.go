// +build !linux !cgo

package seccomp

func InitSeccomp(syscalls []string) error {
	return nil
}
