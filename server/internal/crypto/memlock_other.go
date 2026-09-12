//go:build !linux && !darwin

package crypto

func mlock(b []byte) {}

func munlock(b []byte) {}
