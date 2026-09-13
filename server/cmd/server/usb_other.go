//go:build !linux && !darwin && !windows

package main

// removableMounts is a no-op on unsupported platforms: the operator must pass
// -key explicitly there.
func defaultRemovableMounts() []string {
	return nil
}
