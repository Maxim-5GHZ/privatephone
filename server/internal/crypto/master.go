package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const masterKeySize = 32

// Half-file format (pp.local / pp.key):
//
//	0..7    magic  "PPHALF\x00"
//	8       format version (1)
//	9..24   nodeID — 16 random bytes, identical in both halves of a node
//	25      name length N (0..60)
//	26..    short operator-facing node name (no control characters)
//	..      raw 32 bytes of half material
//
// The on-disk master key is SHA-256(raw_local ‖ raw_usb); neither half alone
// unlocks the vault. nodeID/name are not secret — they only bind the halves to
// a node so the server can tell "this stick belongs to node X" and never offer
// or overwrite a foreign stick by mistake.
const (
	halfVerOffset   = 8
	halfNodeIDStart = 9
	halfNameLenOffs = 25
	halfHeaderLen   = halfNameLenOffs + 1 // magic+ver+nodeID+nameLen
	halfNameMax     = 60
	halfVersion     = 1
)

var halfMagic = []byte("PPHALF\x00")

var (
	// ErrHalfLegacy is returned for a raw 32-byte half file from the pre-nodeID
	// format (no binding): the node must be recreated.
	ErrHalfLegacy = errors.New("legacy half format without node identity — recreate the node")
	// ErrHalfCorrupt is returned when a half file fails the strict format checks.
	ErrHalfCorrupt = errors.New("corrupt half file")
)

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

// HalfInfo is the parsed node identity carried by a half file.
type HalfInfo struct {
	NodeID [16]byte
	Name   string
}

// validateHalfName rejects names with control characters or excessive length.
func validateHalfName(name string) error {
	if len(name) > halfNameMax {
		return fmt.Errorf("node name too long: %d bytes (max %d)", len(name), halfNameMax)
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return fmt.Errorf("node name contains control characters")
		}
	}
	return nil
}

// encodeHalf renders the on-disk half file: header + 32 raw bytes.
func encodeHalf(nodeID [16]byte, name string, raw []byte) []byte {
	buf := make([]byte, halfHeaderLen+len(name)+masterKeySize)
	copy(buf, halfMagic)
	buf[halfVerOffset] = halfVersion
	copy(buf[halfNodeIDStart:halfNameLenOffs], nodeID[:])
	buf[halfNameLenOffs] = byte(len(name))
	copy(buf[halfHeaderLen:halfHeaderLen+len(name)], name)
	copy(buf[halfHeaderLen+len(name):], raw)
	return buf
}

// readHalfRaw reads a half file, strictly validates the header and returns the
// raw half material in a fresh buffer. The intermediate file buffer (which
// holds the raw bytes in the heap) is cleared before returning.
func readHalfRaw(path string) ([]byte, HalfInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, HalfInfo{}, err
	}
	defer clear(b)
	if !bytes.HasPrefix(b, halfMagic) {
		if len(b) == masterKeySize {
			return nil, HalfInfo{}, fmt.Errorf("%w: %s", ErrHalfLegacy, path)
		}
		return nil, HalfInfo{}, fmt.Errorf("%w: %s: bad magic", ErrHalfCorrupt, path)
	}
	if b[halfVerOffset] != halfVersion {
		return nil, HalfInfo{}, fmt.Errorf("%w: %s: unsupported version %d", ErrHalfCorrupt, path, b[halfVerOffset])
	}
	nl := int(b[halfNameLenOffs])
	if len(b) != halfHeaderLen+nl+masterKeySize {
		return nil, HalfInfo{}, fmt.Errorf("%w: %s: bad length %d", ErrHalfCorrupt, path, len(b))
	}
	info := HalfInfo{Name: string(b[halfHeaderLen : halfHeaderLen+nl])}
	copy(info.NodeID[:], b[halfNodeIDStart:halfNameLenOffs])
	if err := validateHalfName(info.Name); err != nil {
		return nil, HalfInfo{}, fmt.Errorf("%w: %s: %v", ErrHalfCorrupt, path, err)
	}
	raw := make([]byte, masterKeySize)
	copy(raw, b[halfHeaderLen+nl:])
	return raw, info, nil
}

// ReadHalfHeader parses only the node identity of a half file, clearing the
// intermediate read buffer (which briefly holds the raw half material).
func ReadHalfHeader(path string) (HalfInfo, error) {
	_, info, err := readHalfRaw(path)
	return info, err
}

// KeyFromHalves recombines the master key from its two persisted halves and
// returns it locked in RAM. Both halves must carry the same nodeID — a foreign
// stick (from another node) is rejected before any vault decryption attempt.
// watchPath is the USB half path, so carrier removal is detected by the
// existing Present/Watch machinery. The raw halves are zeroed in RAM right
// after the combination.
func KeyFromHalves(localPath, usbPath string) (*MasterKey, error) {
	localRaw, localInfo, err := readHalfRaw(localPath)
	if err != nil {
		return nil, err
	}
	defer clear(localRaw)
	usbRaw, usbInfo, err := readHalfRaw(usbPath)
	if err != nil {
		return nil, err
	}
	defer clear(usbRaw)
	if localInfo.NodeID != usbInfo.NodeID {
		return nil, fmt.Errorf("половины разных узлов: %s (%s) не пара к %s (%s)",
			usbPath, shortName(usbInfo), localPath, shortName(localInfo))
	}
	h := sha256.New()
	h.Write(localRaw)
	h.Write(usbRaw)
	return NewMasterKey(h.Sum(nil), usbPath)
}

// shortName renders a half identity for diagnostics.
func shortName(info HalfInfo) string {
	if info.Name != "" {
		return info.Name
	}
	return "node-" + hex.EncodeToString(info.NodeID[:4])
}

// CreateHalvesWithID generates two fresh random halves bound to nodeID (a
// local one next to the data and a USB one on the removable medium), persists
// both with 0600 permissions and returns the combined master key locked in
// RAM. The raw halves and the on-disk buffers are zeroed in RAM right after
// the combination.
func CreateHalvesWithID(localPath, usbPath string, nodeID [16]byte, name string) (*MasterKey, error) {
	if err := validateHalfName(name); err != nil {
		return nil, err
	}
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
	localFile := encodeHalf(nodeID, name, local)
	defer clear(localFile)
	usbFile := encodeHalf(nodeID, name, usb)
	defer clear(usbFile)
	if err := os.WriteFile(localPath, localFile, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(usbPath, usbFile, 0o600); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(local)
	h.Write(usb)
	ok = true
	return NewMasterKey(h.Sum(nil), usbPath)
}

// CreateHalves is a convenience wrapper: it generates a fresh nodeID and an
// empty name. Real deployments should use CreateHalvesWithID so the node name
// is written into the halves.
func CreateHalves(localPath, usbPath string) (*MasterKey, error) {
	var nodeID [16]byte
	if _, err := rand.Read(nodeID[:]); err != nil {
		return nil, err
	}
	return CreateHalvesWithID(localPath, usbPath, nodeID, "")
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
