package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const masterKeySize = 32

// MasterKey holds the 32-byte SQLite vault key in (best-effort) locked memory.
// The master key is either a single full key file (rescue/dev mode, loaded via
// LoadMasterKey) or the SHA-256 combination of two randomly generated halves:
// a local half (<data>/pp.local) and a USB half (<usb>/pp.key). Neither half is
// stored in RAM beyond the load; only the combined key is materialized (locked
// via mlock) and zeroed when the carrier is removed or the process shuts down.
type MasterKey struct {
	key  []byte
	path string
	dead bool
}

// NewMasterKey wraps a 32-byte key src into locked memory. watchPath is where
// Present/Watch poll for carrier presence (the USB half file, or the key file
// itself in single-key mode). src is not modified.
func NewMasterKey(src []byte, watchPath string) (*MasterKey, error) {
	if len(src) != masterKeySize {
		return nil, fmt.Errorf("bad master key size: got %d bytes, want %d", len(src), masterKeySize)
	}
	buf := pageAlignedAlloc(masterKeySize)
	copy(buf, src)
	mlock(buf)
	return &MasterKey{key: buf, path: watchPath}, nil
}

// LoadMasterKey reads a full key file (rescue/legacy single-key mode).
func LoadMasterKey(path string) (*MasterKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return NewMasterKey(data, path)
}

// CreateMasterKey writes a fresh random full key file (rescue/dev mode).
func CreateMasterKey(path string) (*MasterKey, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	buf := pageAlignedAlloc(masterKeySize)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	mlock(buf)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		DestroyBytes(buf)
		return nil, err
	}
	return &MasterKey{key: buf, path: path}, nil
}

// KeyFromHalves recombines the master key from its two persisted halves and
// returns it locked in RAM. watchPath is the USB half path, so carrier removal
// is detected by the existing Present/Watch machinery. The raw halves are
// zeroed in RAM right after the combination.
func KeyFromHalves(localPath, usbPath string) (*MasterKey, error) {
	local, err := os.ReadFile(localPath)
	if err != nil {
		return nil, err
	}
	defer clear(local)
	usb, err := os.ReadFile(usbPath)
	if err != nil {
		return nil, err
	}
	defer clear(usb)
	if len(local) != masterKeySize || len(usb) != masterKeySize {
		return nil, fmt.Errorf("bad half size: local=%d usb=%d bytes, want %d", len(local), len(usb), masterKeySize)
	}
	h := sha256.New()
	h.Write(local)
	h.Write(usb)
	return NewMasterKey(h.Sum(nil), usbPath)
}

// CreateHalves generates two fresh random halves (a local one next to the data
// and a USB one on the removable medium), persists both with 0600 permissions
// and returns the combined master key locked in RAM. The raw halves are zeroed
// in RAM right after the combination.
func CreateHalves(localPath, usbPath string) (*MasterKey, error) {
	for _, p := range []string{localPath, usbPath} {
		if dir := filepath.Dir(p); dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, err
			}
		}
	}
	local := make([]byte, masterKeySize)
	usb := make([]byte, masterKeySize)
	ok := false
	defer func() {
		if !ok {
			DestroyBytes(local)
			DestroyBytes(usb)
		}
	}()
	if _, err := rand.Read(local); err != nil {
		return nil, err
	}
	if _, err := rand.Read(usb); err != nil {
		return nil, err
	}
	if err := os.WriteFile(localPath, local, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(usbPath, usb, 0o600); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(local)
	h.Write(usb)
	ok = true
	return NewMasterKey(h.Sum(nil), usbPath)
}

// Path returns the on-disk location of the key carrier.
func (m *MasterKey) Path() string {
	return m.path
}

// Bytes returns a copy of the key for the caller.
func (m *MasterKey) Bytes() []byte {
	cp := make([]byte, masterKeySize)
	copy(cp, m.key)
	return cp
}

// Present reports whether the carrier is still physically attached.
func (m *MasterKey) Present() bool {
	_, err := os.Stat(m.path)
	return err == nil
}

// Destroy zeroes the key in RAM. Idempotent.
func (m *MasterKey) Destroy() {
	if m == nil || m.dead {
		return
	}
	DestroyBytes(m.key)
	m.dead = true
}

// Watch polls the carrier location and, once it disappears, destroys the key
// and invokes onLoss (the caller is expected to terminate the process hard).
func (m *MasterKey) Watch(interval time.Duration, onLoss func()) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			if !m.Present() {
				m.Destroy()
				onLoss()
				return
			}
		}
	}()
}

// DestroyBytes zeroes a buffer in place.
func DestroyBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	munlock(b)
}

// ErrKeyMissing is returned when the master key carrier is absent.
var ErrKeyMissing = errors.New("master key not found")
