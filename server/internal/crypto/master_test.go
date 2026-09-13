package crypto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMasterKeyLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	mk, err := CreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !mk.Present() {
		t.Fatal("freshly created carrier must be present")
	}
	if mk.Path() != path {
		t.Fatal("Path must report the carrier location")
	}
	if len(mk.Bytes()) != 32 {
		t.Fatalf("key size %d, want 32", len(mk.Bytes()))
	}

	loaded, err := LoadMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mk.Bytes(), loaded.Bytes()) {
		t.Fatal("reloaded key must match created key")
	}
	if got, err := os.Stat(path); err != nil || got.Size() != 32 {
		t.Fatalf("key file must be 32 bytes on disk, got %v err=%v", got, err)
	}

	loaded.Destroy()
	if !loaded.dead {
		t.Fatal("Destroy must mark the key dead")
	}
	loaded.Destroy()
	if len(mk.Bytes()) != 32 {
		t.Fatal("destroying the loaded copy must not clobber the original")
	}
	mk.Destroy()
	if !allZero(mk.Bytes()) {
		t.Fatal("destroyed key must be zeroed")
	}
	mk.Destroy()

	if _, err := LoadMasterKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing carrier must not load")
	}
	small := filepath.Join(t.TempDir(), "small")
	if err := os.WriteFile(small, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKey(small); err == nil {
		t.Fatal("wrong-size key file must be rejected")
	}
}

func TestMasterKeyWatchFiresOnUnlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	mk, err := CreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Destroy()

	loss := make(chan struct{})
	mk.Watch(10*time.Millisecond, func() { close(loss) })
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	select {
	case <-loss:
	case <-time.After(3 * time.Second):
		t.Fatal("Watch must fire when the carrier is removed")
	}
	if !allZero(mk.Bytes()) {
		t.Fatal("key must be destroyed on carrier loss")
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestCreateMasterKeyFailsOnUnwritable(t *testing.T) {
	_, err := CreateMasterKey(t.TempDir()) // writing into a directory must fail
	if err == nil {
		t.Fatal("master key creation must fail when the carrier path is unwritable")
	}
}

func TestWriteSelfSignedTLSCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	if err := WriteSelfSignedTLSCert(certPath, keyPath, []string{"192.168.1.10", "not-an-ip", "300.1.1.1"}, "test-org"); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(certPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("cert file must be PEM")
	}
	if !bytes.Contains(keyPEM, []byte("EC PRIVATE KEY")) {
		t.Fatal("key file must be EC PRIVATE KEY PEM")
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair must load: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("cert parse: %v", err)
	}
	if leaf.IPAddresses == nil || len(leaf.IPAddresses) == 0 {
		t.Fatal("cert must carry IP SANs")
	}
	found := false
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "192.168.1.10" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 192.168.1.10 in SANs, got %v", leaf.IPAddresses)
	}
	if err := leaf.VerifyHostname("192.168.1.10"); err != nil {
		t.Fatalf("verify of self-signed cert against its own SAN failed: %v", err)
	}
	if time.Until(leaf.NotAfter).Hours() < 24*365*9 {
		t.Fatalf("cert must be valid ~10y, NotAfter=%v", leaf.NotAfter)
	}
	if time.Since(leaf.NotBefore).Hours() > 2 {
		t.Fatalf("cert must be backdated for skew, NotBefore=%v", leaf.NotBefore)
	}
}
