package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestNewID(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("NewID must return 16 hex chars, got %q and %q", a, b)
	}
	if a == b {
		t.Fatal("two consecutive IDs must differ")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := PublicKeyToPEM(&priv.PublicKey)
	pub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"lat":55.1,"lon":37.2,"type":"own","n":"ab"}`)
	canon := Canonical("marker", "alpha", "nonce-1", time.Now().Unix(), body)

	sig, err := Sign(priv, canon)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, canon, sig) {
		t.Fatal("signature should verify")
	}

	tampered := Canonical("marker", "alpha", "nonce-1", time.Now().Unix(), []byte(`{"lat":55.1,"lon":37.2,"type":"enemy"}`))
	if Verify(pub, tampered, sig) {
		t.Fatal("tampered body must not verify")
	}
}

func TestCanonicalDeterministic(t *testing.T) {
	body := []byte(`{"a":1}`)
	a := Canonical("m", "s", "n", 123, body)
	b := Canonical("m", "s", "n", 123, body)
	if !bytes.Equal(a, b) {
		t.Fatal("canonical must be deterministic")
	}
}

func TestReplayGuard(t *testing.T) {
	g := NewReplayGuard(10, DefaultSkewWindow)
	now := time.Now().Unix()
	if !g.CheckAt(now, "n1", now) {
		t.Fatal("fresh nonce must be accepted")
	}
	if g.CheckAt(now, "n1", now) {
		t.Fatal("replayed nonce must be rejected")
	}
	if g.CheckAt(now, "n2", now+3600) {
		t.Fatal("future timestamp must be rejected")
	}
	if g.CheckAt(now, "n3", now-3600) {
		t.Fatal("stale timestamp must be rejected")
	}
}

func TestReplayGuardWindow(t *testing.T) {
	g := NewReplayGuard(10, 30*time.Second)
	now := int64(2_000_000_000)
	if !g.CheckAt(now, "ok-edge", now+30) {
		t.Fatal("timestamp at the exact window edge must pass")
	}
	if g.CheckAt(now+31, "out", now+31+30+1) {
		t.Fatal("timestamp beyond the explicit window must be rejected")
	}
	if !g.CheckAt(now+31, "in", now+31) {
		t.Fatal("timestamp inside the explicit window must pass")
	}
}

func TestClockOffset(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	c := NewClockOffset()

	// Far-future admin ts is clamped to MaxClockCorrection, not swallowed whole.
	c.Observe(now, now.Unix()-4*3600)
	if got := c.Offset(); got != -MaxClockCorrection {
		t.Fatalf("expected clamp to -%s, got %s", MaxClockCorrection, got)
	}
	// A normal +60s drift sample is taken as-is.
	c.Observe(now, now.Unix()+60)
	if got := c.Offset(); got != 60*time.Second {
		t.Fatalf("expected offset 1m, got %s", got)
	}
	if got := c.AdjustedNow(now); !got.Equal(now.Add(60 * time.Second)) {
		t.Fatalf("AdjustedNow must shift by the learned offset, got %s", got)
	}
	// A third sample exercises the EMA branch (α=0.25): 60 + (120-60)/4 = 75.
	c.Observe(now, now.Unix()+120)
	if got := c.Offset(); got != 75*time.Second {
		t.Fatalf("expected EMA offset 75s, got %s", got)
	}
	// The positive bound is clamped just like the negative one (first sample).
	c2 := NewClockOffset()
	c2.Observe(now, now.Unix()+5*3600)
	if got := c2.Offset(); got != MaxClockCorrection {
		t.Fatalf("expected clamp to +%s, got %s", MaxClockCorrection, got)
	}
}

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(privPEM, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("private key PEM must be PKCS#8")
	}
	restored, err := ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if restored.X.Cmp(priv.X) != 0 || restored.Y.Cmp(priv.Y) != 0 || restored.D.Cmp(priv.D) != 0 {
		t.Fatal("restored key must match the original")
	}

	pubPEM, err := PublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParsePrivateKeyPEM(pubPEM)
	if err == nil {
		t.Fatal("a public key must not parse as a private key")
	}
}

func TestParseKeyPEMErrorPaths(t *testing.T) {
	if _, err := ParsePrivateKeyPEM([]byte("junk")); err == nil {
		t.Fatal("junk must not parse as a private key")
	}
	if _, err := ParsePublicKeyPEM([]byte("junk")); err == nil {
		t.Fatal("junk must not parse as a public key")
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParsePrivateKeyPEM(rsaPEM); err == nil {
		t.Fatal("an RSA private key must be rejected as not ECDSA")
	}

	rsaPubDER, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubDER})
	if _, err := ParsePublicKeyPEM(rsaPubPEM); err == nil {
		t.Fatal("an RSA public key must be rejected as not ECDSA")
	}
}

func TestVerifyRejectsBadSignatures(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	canon := Canonical("marker", "alpha", "n", 1, []byte(`{}`))
	if Verify(&priv.PublicKey, canon, "!!!not-base64!!!") {
		t.Fatal("garbage base64 signature must not verify")
	}
	if Verify(&priv.PublicKey, canon, "") {
		t.Fatal("empty signature must not verify")
	}
}

func TestReplayGuardDefaultWindowAndCheck(t *testing.T) {
	g := NewReplayGuard(4, 0) // window <= 0 falls back to DefaultSkewWindow
	now := time.Now().Unix()
	if !g.Check("n-default", now) {
		t.Fatal("fresh nonce through the real-clock Check must pass")
	}
	if g.Check("n-default", now) {
		t.Fatal("replayed nonce must fail")
	}
}

func TestReplayGuardPrunesOldEntries(t *testing.T) {
	g := NewReplayGuard(1, DefaultSkewWindow)
	now := time.Now().Unix()
	if !g.CheckAt(now, "a", now) {
		t.Fatal("first nonce must pass")
	}
	if !g.CheckAt(now+10, "b", now+10) {
		t.Fatal("second nonce must pass once the cache overflows and prunes")
	}
}

func TestMasterKeyDestroy(t *testing.T) {
	mk, err := CreateMasterKey(t.TempDir() + "/k.bin")
	if err != nil {
		t.Fatal(err)
	}
	got := mk.Bytes()
	zeroed := true
	for i := range got {
		if got[i] != 0 {
			zeroed = false
		}
	}
	if zeroed {
		t.Fatal("fresh key must not be all zeros")
	}
	mk.Destroy()
	allZero := true
	for i := range mk.key {
		if mk.key[i] != 0 {
			allZero = false
		}
	}
	if !allZero {
		t.Fatal("key must be zeroed after Destroy")
	}
}
