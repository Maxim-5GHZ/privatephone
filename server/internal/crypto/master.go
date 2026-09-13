package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const masterKeySize = 32

// MasterKey holds the 32-byte SQLite vault key in (best-effort) locked memory.
// It is loaded from a USB flash drive at startup and zeroed when the carrier is
// removed or the process shuts down.
type MasterKey struct {
	key  []byte
	path string
	dead bool
}

// LoadMasterKey reads the key file from the removable medium.
func LoadMasterKey(path string) (*MasterKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != masterKeySize {
		return nil, fmt.Errorf("bad master key size: got %d bytes, want %d", len(data), masterKeySize)
	}
	buf := pageAlignedAlloc(masterKeySize)
	copy(buf, data)
	clear(data)
	mlock(buf)
	return &MasterKey{key: buf, path: path}, nil
}

// CreateMasterKey writes a fresh random key to the removable medium.
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
