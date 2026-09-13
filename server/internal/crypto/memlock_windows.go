//go:build windows

package crypto

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows default page size. Large pages are opt-in and require the
// SeLockMemoryPrivilege; VirtualLock implies it, so 4K is safe in practice.
const pageSize = 4096

var (
	regMu sync.Mutex
	reg   = map[uintptr]uintptr{} // page-aligned base -> locked length
)

// pageAlignedAlloc returns a buffer whose backing store starts at a page
// boundary and whose cap is a whole number of pages, so that VirtualLock can
// pin it. The returned slice has len == n so existing key-size checks hold.
func pageAlignedAlloc(n int) []byte {
	if n <= 0 {
		return []byte{}
	}
	size := pageSize
	for size < n {
		size += pageSize
	}
	raw := make([]byte, size+pageSize) // +1 page headroom to align the start
	base := uintptr(unsafe.Pointer(&raw[0]))
	base &= pageSize - 1
	off := pageSize - int(base)
	if off == 0 {
		off = pageSize // raw[0] was already aligned; use the surplus page
	}
	aligned := raw[off : off+size] // &aligned[0] is page-aligned, cap==size
	return aligned[:n]
}

// mlock pins the key so it is never paged to swap or written into a Windows
// crash dump. VirtualLock needs a page-aligned range — pageAlignedAlloc
// guarantees that, and the registry keeps the full locked length for munlock.
func mlock(b []byte) {
	if len(b) == 0 {
		return
	}
	base := uintptr(unsafe.Pointer(&b[0]))
	size := uintptr(cap(b))
	regMu.Lock()
	reg[base] = size
	regMu.Unlock()
	_ = windows.VirtualLock(base, size)
}

func munlock(b []byte) {
	if len(b) == 0 {
		return
	}
	base := uintptr(unsafe.Pointer(&b[0]))
	regMu.Lock()
	size, ok := reg[base]
	delete(reg, base)
	regMu.Unlock()
	if ok {
		_ = windows.VirtualUnlock(base, size)
	}
}
