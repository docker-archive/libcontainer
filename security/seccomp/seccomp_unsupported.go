// +build !linux !cgo !seccomp

package seccomp

// Seccomp not supported, do nothing
func InitSeccomp(config *Config) error {
	return nil
}
