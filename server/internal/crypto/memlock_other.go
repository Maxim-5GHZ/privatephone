//go:build !linux && !darwin && !windows

package crypto

func mlock(b []byte) {}

func munlock(b []byte) {}

func pageAlignedAlloc(n int) []byte {
	return make([]byte, n)
}
