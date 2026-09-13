package protocol

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"testing"
	"time"

	"privatephone/server/internal/crypto"
)

type testIdentity struct {
	priv *ecdsa.PrivateKey
	role string
}

// newRoster builds N keys and a SubscriberLookup over them, keyed by callsign.
func newRoster(t *testing.T, roles map[string]string) (map[string]*testIdentity, SubscriberLookup) {
	t.Helper()
	ids := map[string]*testIdentity{}
	lookup := func(ctx context.Context, callsign string) (string, string, error) {
		id, ok := ids[callsign]
		if !ok {
			return "", "", ErrUnknownSender
		}
		pubPEM, _ := crypto.PublicKeyToPEM(&id.priv.PublicKey)
		return string(pubPEM), id.role, nil
	}
	for name, role := range roles {
		priv, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = &testIdentity{priv: priv, role: role}
	}
	return ids, lookup
}

func signFrameForTest(t *testing.T, callsign string, id *testIdentity, nonce string, ts int64) *Envelope {
	t.Helper()
	ev := &Envelope{
		Sender:    callsign,
		TS:        ts,
		Nonce:     nonce,
		Kind:      "ping",
		Signature: "",
		Data:      []byte(`{}`),
	}
	sig, err := crypto.Sign(id.priv, ev.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	ev.Signature = sig
	return ev
}

func TestAdminCalibratesSkew(t *testing.T) {
	ids, lookup := newRoster(t, map[string]string{"admin": "admin"})
	ver := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs:  lookup,
		Skew:  crypto.NewClockOffset(),
	}
	now := time.Now().Unix()
	// Admin's packets carry ts 20m ahead of the node's clock (admin device and
	// subscribers share a faster clock; only the node lags). Without
	// calibration this would be stale-rejected because the window is 10m.
	ev := signFrameForTest(t, "admin", ids["admin"], "a1", now+1200)
	if _, err := ver.Verify(context.Background(), ev); err != nil {
		t.Fatalf("admin packet with node-skewed clock must be accepted after calibration: %v", err)
	}
	if d := ver.Skew.Offset() - 20*time.Minute; d < -time.Second || d > time.Second {
		t.Fatalf("expected learned offset ~20m (tolerance 1s), got %s", ver.Skew.Offset())
	}
}

func TestSubscriberAcceptsAfterAdminCalibration(t *testing.T) {
	roles := map[string]string{"admin": "admin", "agent": "agent"}
	ids, lookup := newRoster(t, roles)
	withCal := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs:  lookup,
		Skew:  crypto.NewClockOffset(),
	}
	withoutCal := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs:  lookup,
	}
	ctx := context.Background()
	now := time.Now().Unix()
	// First the admin's clock-skewed ping calibrates the offset.
	adminEv := signFrameForTest(t, "admin", ids["admin"], "c0", now+1200)
	if _, err := withCal.Verify(ctx, adminEv); err != nil {
		t.Fatalf("admin calibration failed: %v", err)
	}
	// Subscribers are on the same (admin) clock: 20m ahead of the node.
	agentEv := signFrameForTest(t, "agent", ids["agent"], "c1", now+1200)
	if _, err := withCal.Verify(ctx, agentEv); err != nil {
		t.Fatalf("subscriber on the admin clock must be accepted once offset is learned: %v", err)
	}
	if _, err := withoutCal.Verify(ctx, agentEv); err != ErrReplay {
		t.Fatalf("without calibration the same stale packet must be rejected, got %v", err)
	}
}

func TestNonAdminDoesNotFeedEstimator(t *testing.T) {
	ids, lookup := newRoster(t, map[string]string{"admin": "admin", "agent": "agent"})
	ver := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs:  lookup,
		Skew:  crypto.NewClockOffset(),
	}
	// A signed agent packet 20m in the future is rejected and MUST NOT move the
	// estimator — only admin packets are the time authority.
	ev := signFrameForTest(t, "agent", ids["agent"], "s1", time.Now().Unix()+1200)
	if _, err := ver.Verify(context.Background(), ev); err != ErrReplay {
		t.Fatalf("future agent packet must be stale-rejected, got %v", err)
	}
	if got := ver.Skew.Offset(); got != 0 {
		t.Fatalf("agent packets must not feed the clock estimator, offset=%s", got)
	}
}

func TestVerifyRejectsMalformedPackets(t *testing.T) {
	ids, lookup := newRoster(t, map[string]string{"admin": "admin"})
	ver := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs:  lookup,
	}
	ctx := context.Background()

	if _, err := ver.Verify(ctx, nil); err != ErrBadSignature {
		t.Fatalf("nil envelope must be rejected as bad signature, got %v", err)
	}
	if _, err := ver.Verify(ctx, &Envelope{Sender: "", Kind: "k", Nonce: "n", Signature: "s"}); err != ErrBadSignature {
		t.Fatalf("empty sender must be rejected, got %v", err)
	}
	if _, err := ver.Verify(ctx, &Envelope{Sender: "admin", Kind: "", Nonce: "n", Signature: "s"}); err != ErrBadSignature {
		t.Fatalf("empty kind must be rejected, got %v", err)
	}

	ev := signFrameForTest(t, "ghost", ids["admin"], "u1", time.Now().Unix())
	if _, err := ver.Verify(ctx, ev); err != ErrUnknownSender {
		t.Fatalf("unknown sender must be rejected, got %v", err)
	}

	ev = signFrameForTest(t, "admin", ids["admin"], "u2", time.Now().Unix())
	ev.Signature = "AAAA"
	if _, err := ver.Verify(ctx, ev); err != ErrBadSignature {
		t.Fatalf("forged signature must be rejected, got %v", err)
	}
}

func TestVerifyStoredSkipsFreshness(t *testing.T) {
	ids, lookup := newRoster(t, map[string]string{"agent": "agent"})
	ver := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs:  lookup,
	}
	ctx := context.Background()
	old := time.Now().Unix() - 24*3600

	ev := signFrameForTest(t, "agent", ids["agent"], "old-1", old)
	if _, err := ver.Verify(ctx, ev); err != ErrReplay {
		t.Fatalf("a day-old packet must fail the live freshness check, got %v", err)
	}
	role, err := ver.VerifyStored(ctx, ev)
	if err != nil || role != "agent" {
		t.Fatalf("VerifyStored must accept historical packets without the guard, role=%q err=%v", role, err)
	}
	if _, err := ver.VerifyStored(ctx, nil); err != ErrBadSignature {
		t.Fatalf("nil envelope must be rejected, got %v", err)
	}

	bad := signFrameForTest(t, "agent", ids["agent"], "old-2", old)
	bad.Data = []byte(`{"tampered":true}`)
	if _, err := ver.VerifyStored(ctx, bad); err != ErrBadSignature {
		t.Fatalf("tampered stored packet must be rejected, got %v", err)
	}
}

func TestRoleAndEmptyPubLookup(t *testing.T) {
	ids, lookup := newRoster(t, map[string]string{"agent": "agent"})
	ver := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs:  lookup,
	}
	ctx := context.Background()
	role, err := ver.Role(ctx, "agent")
	if err != nil || role != "agent" {
		t.Fatalf("Role must return the stored role, got %q/%v", role, err)
	}
	if _, err := ver.Role(ctx, "ghost"); err != ErrUnknownSender {
		t.Fatalf("Role of an unknown callsign must be ErrUnknownSender, got %v", err)
	}

	// A lookup that returns a registered role but no public key must read as
	// ErrUnknownSender, never panic or fall through to signature verification.
	emptyPub := &Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs: func(ctx context.Context, callsign string) (string, string, error) {
			return "", "agent", nil
		},
	}
	ev := signFrameForTest(t, "agent", ids["agent"], "e1", time.Now().Unix())
	if _, err := emptyPub.Verify(ctx, ev); err != ErrUnknownSender {
		t.Fatalf("empty stored public key must be rejected as unknown sender, got %v", err)
	}
}

func TestFrameEnvelopeMapping(t *testing.T) {
	f := Frame{
		Sender:    "alpha",
		TS:        42,
		Nonce:     "n1",
		Kind:      "marker",
		Signature: "sig",
		Data:      json.RawMessage(`{"lat":1}`),
	}
	ev := f.Envelope()
	if ev.Sender != "alpha" || ev.Kind != "marker" || ev.Nonce != "n1" || ev.TS != 42 {
		t.Fatalf("Envelope must preserve the wire frame, got %+v", ev)
	}
	if string(ev.Data) != `{"lat":1}` {
		t.Fatalf("Envelope must preserve the raw body, got %s", ev.Data)
	}
}
