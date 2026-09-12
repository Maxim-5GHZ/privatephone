//go:build linux || darwin

package crypto

import "syscall"

// mlock pins memory so the key is never paged to swap. Best-effort on Linux.
func mlock(b []byte) {
	_ = syscall.Mlock(b)
}

// munlock releases the pin after destruction.
func munlock(b []byte) {
	_ = syscall.Munlock(b)
}
