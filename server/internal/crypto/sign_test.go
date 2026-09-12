package crypto

import (
	"bytes"
	"testing"
	"time"
)

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
	g := NewReplayGuard(10)
	now := time.Now().Unix()
	if !g.Check("n1", now) {
		t.Fatal("fresh nonce must be accepted")
	}
	if g.Check("n1", now) {
		t.Fatal("replayed nonce must be rejected")
	}
	if g.Check("n2", now+3600) {
		t.Fatal("future timestamp must be rejected")
	}
	if g.Check("n3", now-3600) {
		t.Fatal("stale timestamp must be rejected")
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
