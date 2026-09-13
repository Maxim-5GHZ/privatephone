package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadCertPEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: no pem block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cert
}

func TestWriteCAChain(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	leafCert := filepath.Join(dir, "tls.crt")
	leafKey := filepath.Join(dir, "tls.key")

	if err := WriteCACert(caCert, caKey, "PrivatePhone Mesh CA"); err != nil {
		t.Fatalf("WriteCACert: %v", err)
	}
	if err := WriteServerTLSCert(caCert, caKey, leafCert, leafKey, []string{"192.168.1.10", "not-an-ip"}, "ПАК АСК offline node"); err != nil {
		t.Fatalf("WriteServerTLSCert: %v", err)
	}

	ca := loadCertPEM(t, caCert)
	leaf := loadCertPEM(t, leafCert)

	if !ca.IsCA {
		t.Fatal("CA cert must be a CA")
	}
	if ca.MaxPathLen != 0 {
		t.Fatalf("CA must forbid sub-CAs, got MaxPathLen=%d", ca.MaxPathLen)
	}
	if ca.NotAfter.Sub(ca.NotBefore) < 9*365*24*time.Hour {
		t.Fatal("CA validity must span ~10 years")
	}
	if !ca.NotBefore.Before(time.Now()) {
		t.Fatal("CA NotBefore must be backdated for clock skew")
	}

	if leaf.NotAfter.Sub(leaf.NotBefore) < 9*365*24*time.Hour {
		t.Fatal("leaf validity must span ~10 years")
	}
	pool := x509.NewCertPool()
	if caCertPEM, _ := os.ReadFile(caCert); !pool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("cannot load CA into the trust pool")
	}
	if err := leaf.VerifyHostname("192.168.1.10"); err != nil {
		t.Fatalf("leaf must verify hostname against SAN IP: %v", err)
	}
	chain, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("leaf must chain to the CA: %v", err)
	}
	if len(chain[0]) != 2 {
		t.Fatalf("expected [leaf, CA] chain, got %d certs", len(chain[0]))
	}
	if _, err := os.Stat(leafKey); err != nil {
		t.Fatalf("leaf key must be written: %v", err)
	}
}

func TestWriteServerTLSCertFailsWithoutCA(t *testing.T) {
	dir := t.TempDir()
	err := WriteServerTLSCert(
		filepath.Join(dir, "missing.crt"),
		filepath.Join(dir, "missing.key"),
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil, "org")
	if err == nil {
		t.Fatal("issuing a leaf without a CA must fail loudly, not produce an untrusted cert")
	}
}

// TestWriteServerTLSCertErrorPaths drives every deliberate failure mode of the
// CA-driven leaf issuance so a broken CA setup never silently misbehaves.
func TestWriteServerTLSCertErrorPaths(t *testing.T) {
	dir := t.TempDir()
	leafCert := filepath.Join(dir, "tls.crt")
	leafKey := filepath.Join(dir, "tls.key")
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// CA cert PEM garbage -> "bad CA pem on disk"
	garbageCert := write("g1.crt", []byte("not a pem block"))
	garbageKey := write("g1.key", []byte("not a pem block"))
	if err := WriteServerTLSCert(garbageCert, garbageKey, leafCert+"a", leafKey+"a", nil, "o"); err == nil {
		t.Fatal("garbage CA PEM must be rejected")
	}

	// CA cert PEM parses but the CA key is RSA (not EC) -> "CA key is not an EC key"
	caCertDir := t.TempDir()
	caCertPath := filepath.Join(caCertDir, "ca.crt")
	caKeyPath := filepath.Join(caCertDir, "ca.key")
	if err := WriteCACert(caCertPath, caKeyPath, "CA"); err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	rsaCAKey := write("rsa.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}))
	if err := WriteServerTLSCert(caCertPath, rsaCAKey, leafCert+"b", leafKey+"b", nil, "o"); err == nil {
		t.Fatal("a non-EC CA key must be rejected")
	}

	// CA PEM that is a valid cert but not a CA -> "CA certificate is not a CA"
	ssCert := filepath.Join(caCertDir, "self.crt")
	ssKey := filepath.Join(caCertDir, "self.key")
	if err := WriteSelfSignedTLSCert(ssCert, ssKey, nil, "not-a-ca"); err != nil {
		t.Fatal(err)
	}
	if err := WriteServerTLSCert(ssCert, ssKey, leafCert+"c", leafKey+"c", nil, "o"); err == nil {
		t.Fatal("a non-CA certificate must not be accepted as a CA")
	}

	// CA cert parses but is a broken x509 blob -> parse error
	broken := write("broken.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk der")}))
	if err := WriteServerTLSCert(broken, rsaCAKey, leafCert+"d", leafKey+"d", nil, "o"); err == nil {
		t.Fatal("unparseable CA cert blob must be rejected")
	}
}

// TestWriteCertFailsOnUnwritablePath covers the file-write failure branches of
// the self-signed and CA writers (writing into a directory path).
func TestWriteCertFailsOnUnwritablePath(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSelfSignedTLSCert(dir, filepath.Join(dir, "k.key"), nil, "o"); err == nil {
		t.Fatal("self-signed writer must fail when the cert path is an unwritable directory")
	}
	if err := WriteCACert(dir, filepath.Join(dir, "ca.key"), "CA"); err == nil {
		t.Fatal("CA writer must fail when the cert path is an unwritable directory")
	}
	if err := WriteSelfSignedTLSCert(filepath.Join(dir, "ok.crt"), dir, nil, "o"); err == nil {
		t.Fatal("self-signed writer must fail when the key path is an unwritable directory")
	}
}
