package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Canonical produces the exact byte string that is signed and verified on both
// the client (WebCrypto) and the server. The body is the raw JSON bytes of the
// "data" payload — nothing is reformatted, so bytes are identical on both ends.
func Canonical(kind, sender, nonce string, ts int64, body []byte) []byte {
	var b strings.Builder
	b.Grow(len(body) + 128)
	b.WriteString("v=1\n")
	b.WriteString("kind=")
	b.WriteString(kind)
	b.WriteByte('\n')
	b.WriteString("sender=")
	b.WriteString(sender)
	b.WriteByte('\n')
	b.WriteString("ts=")
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteByte('\n')
	b.WriteString("nonce=")
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.Write(body)
	return []byte(b.String())
}

// Sign returns base64(std) ECDSA-SHA256 signature of canonical bytes.
func Sign(priv *ecdsa.PrivateKey, canonical []byte) (string, error) {
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks base64(std) ECDSA signature over canonical bytes.
func Verify(pub *ecdsa.PublicKey, canonical []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(canonical)
	return ecdsa.VerifyASN1(pub, hash[:], sig)
}

// ReplayGuard rejects replayed nonces and out-of-window timestamps.
type ReplayGuard struct {
	mu     sync.Mutex
	seen   map[string]int64
	max    int
	window time.Duration
}

// DefaultSkewWindow is the default freshness window: how far a packet
// timestamp may be from "now" before it is judged replayed or stale.
const DefaultSkewWindow = 10 * time.Minute

// NewReplayGuard returns a guard that accepts packets within window of the
// caller's clock (default 10 minutes). Use CheckAt to supply an offset clock.
func NewReplayGuard(max int, window time.Duration) *ReplayGuard {
	if window <= 0 {
		window = DefaultSkewWindow
	}
	return &ReplayGuard{seen: make(map[string]int64), max: max, window: window}
}

// Check reports whether the (nonce, ts) pair is fresh using the real clock.
func (g *ReplayGuard) Check(nonce string, ts int64) bool {
	return g.CheckAt(time.Now().Unix(), nonce, ts)
}

// CheckAt reports whether the (nonce, ts) pair is fresh when the caller's
// notion of "now" is nowSec (Unix seconds), possibly adjusted by a ClockOffset.
func (g *ReplayGuard) CheckAt(nowSec int64, nonce string, ts int64) bool {
	if ts < nowSec-int64(g.window/time.Second) || ts > nowSec+int64(g.window/time.Second) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.seen[nonce]; dup {
		return false
	}
	g.seen[nonce] = ts
	if len(g.seen) > g.max {
		cutoff := nowSec - int64(g.window/time.Second)
		for n, t := range g.seen {
			if t < cutoff {
				delete(g.seen, n)
			}
		}
	}
	return true
}
