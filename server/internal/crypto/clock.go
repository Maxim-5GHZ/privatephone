package crypto

import (
	"sync"
	"time"
)

// ClockOffset learns the node-vs-network clock offset from admin packets whose
// signed "ts" is authoritative operator time. The offline mesh has no NTP, so
// this is the only way to follow admin clock drift without manual config.
//
// The estimate is an EMA: fast to adapt on the first sample, slow to be fooled
// by a single bad packet. Corrections are clamped to ±30 minutes so that one
// malicious/erroneous packet cannot make the server stop accepting packets.
type ClockOffset struct {
	mu      sync.Mutex
	offset  time.Duration
	samples int
}

// MaxClockCorrection bounds how far we ever trust the estimate to move the
// node clock; beyond this the operator must fix the clock manually.
const MaxClockCorrection = 30 * time.Minute

// NewClockOffset returns an estimator that initially reports zero offset.
func NewClockOffset() *ClockOffset { return &ClockOffset{} }

// Observe feeds one trusted sample: the packet timestamp ts (Unix seconds)
// signed by an admin key, observed at real time now. It returns the offset
// that was applied (now → node time).
func (c *ClockOffset) Observe(now time.Time, ts int64) time.Duration {
	delta := time.Unix(ts, 0).Sub(now)
	if delta > MaxClockCorrection {
		delta = MaxClockCorrection
	}
	if delta < -MaxClockCorrection {
		delta = -MaxClockCorrection
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.samples == 0 || c.samples == 1 {
		c.offset = delta
	} else {
		c.offset += (delta - c.offset) / 4 // EMA with α=0.25
	}
	c.samples++
	return c.offset
}

// AdjustedNow returns the caller-supplied "now" shifted by the learned offset.
// This is what should be passed to Guard.CheckAt so window checks compare
// against network time rather than the (possibly drifting) node clock.
func (c *ClockOffset) AdjustedNow(now time.Time) time.Time {
	c.mu.Lock()
	off := c.offset
	c.mu.Unlock()
	return now.Add(off)
}

// Offset returns the currently learned offset.
func (c *ClockOffset) Offset() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offset
}
