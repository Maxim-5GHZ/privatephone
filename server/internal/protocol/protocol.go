package protocol

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"

	"privatephone/server/internal/crypto"
)

// Frame is the signed wire unit used by both the REST envelope and the
// WebSocket channel.
type Frame struct {
	Sender    string          `json:"sender"`
	TS        int64           `json:"ts"`
	Nonce     string          `json:"nonce"`
	Kind      string          `json:"kind"`
	Signature string          `json:"signature"`
	Data      json.RawMessage `json:"data"`
}

// Envelope is the parsed, not-yet-verified request.
type Envelope struct {
	Sender    string
	TS        int64
	Nonce     string
	Kind      string
	Signature string
	Data      []byte
}

func (f *Frame) Envelope() *Envelope {
	return &Envelope{
		Sender:    f.Sender,
		TS:        f.TS,
		Nonce:     f.Nonce,
		Kind:      f.Kind,
		Signature: f.Signature,
		Data:      f.Data,
	}
}

func (e *Envelope) Canonical() []byte {
	return crypto.Canonical(e.Kind, e.Sender, e.Nonce, e.TS, e.Data)
}

var (
	ErrReplay        = errors.New("replayed or stale packet")
	ErrUnknownSender = errors.New("unknown sender")
	ErrBadSignature  = errors.New("invalid signature")
	ErrRevoked       = errors.New("revoked")
)

// SubscriberLookup returns the registered public key PEM and role for a
// callsign. The protocol package stays decoupled from the db package.
type SubscriberLookup func(ctx context.Context, callsign string) (pubKeyPEM, role string, err error)

// Verifier performs signature + freshness + identity checks for every packet.
type Verifier struct {
	Guard *crypto.ReplayGuard
	Subs  SubscriberLookup
}

// Verify returns the caller's role when the packet is authentic.
func (v *Verifier) Verify(ctx context.Context, ev *Envelope) (string, error) {
	if ev == nil || ev.Sender == "" || ev.Kind == "" || ev.Nonce == "" || ev.Signature == "" {
		return "", ErrBadSignature
	}
	if !v.Guard.Check(ev.Nonce, ev.TS) {
		return "", ErrReplay
	}
	role, pub, err := v.lookup(ctx, ev.Sender)
	if err != nil {
		return "", err
	}
	if !crypto.Verify(pub, ev.Canonical(), ev.Signature) {
		return "", ErrBadSignature
	}
	return role, nil
}

// VerifyStored verifies authenticity of a historical packet without touching
// the replay guard or the freshness window. It is used when re-importing
// journal bags (sneaker-net), where packets keep their original ts/nonce and
// must not be misjudged as stale or replayed.
func (v *Verifier) VerifyStored(ctx context.Context, ev *Envelope) (string, error) {
	if ev == nil || ev.Sender == "" || ev.Kind == "" || ev.Nonce == "" || ev.Signature == "" {
		return "", ErrBadSignature
	}
	role, pub, err := v.lookup(ctx, ev.Sender)
	if err != nil {
		return "", err
	}
	if !crypto.Verify(pub, ev.Canonical(), ev.Signature) {
		return "", ErrBadSignature
	}
	return role, nil
}

// Role returns the stored role for a callsign without consuming a nonce; used
// for authorization alongside an already-verified packet (e.g. marker deletion).
func (v *Verifier) Role(ctx context.Context, callsign string) (string, error) {
	role, _, err := v.lookup(ctx, callsign)
	return role, err
}

func (v *Verifier) lookup(ctx context.Context, callsign string) (string, *ecdsa.PublicKey, error) {
	pubPEM, role, err := v.Subs(ctx, callsign)
	if err != nil {
		return "", nil, err
	}
	if pubPEM == "" {
		return "", nil, ErrUnknownSender
	}
	pub, err := crypto.ParsePublicKeyPEM([]byte(pubPEM))
	if err != nil {
		return "", nil, ErrUnknownSender
	}
	return role, pub, nil
}
