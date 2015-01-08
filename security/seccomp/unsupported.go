// +build !linux !cgo !seccomp

package seccomp

func InitSeccomp(config SeccompConfig) error {
	return nil
}
