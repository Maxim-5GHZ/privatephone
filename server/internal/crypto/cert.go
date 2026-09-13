package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// WriteSelfSignedTLSCert generates an ECDSA P-256 self-signed certificate valid
// for 10 years (backdated an hour for clock skew) and writes cert+key files.
// WebRTC getUserMedia requires a secure context, so the node must be reachable
// over HTTPS by its LAN IPs, which are passed in ips.
func WriteSelfSignedTLSCert(certPath, keyPath string, ips []string, org string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{org}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, parsed)
		}
	}
	if len(tmpl.IPAddresses) == 0 {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("::1"))

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	dir, _ := filepath.Split(certPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// WriteCACert generates the mesh-internal certificate authority: a self-signed
// ECDSA P-256 CA valid 10 years whose only job is signing per-node TLS leaf
// certificates. Distributing this single root once into every subscriber
// device's trust store replaces the per-node "install unsigned cert" dance.
func WriteCACert(caCertPath, caKeyPath, org string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{org}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(caCertPath), 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// WriteServerTLSCert issues a node leaf certificate signed by the mesh CA. The
// leaf carries the node's LAN IP SANs (secure context for WebRTC) and is valid
// 10 years. Loading errors surface here, so a broken CA setup never silently
// produces an untrusted cert.
func WriteServerTLSCert(caCertPath, caKeyPath, certPath, keyPath string, ips []string, org string) error {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return err
	}
	caBlock, _ := pem.Decode(caCertPEM)
	keyBlock, _ := pem.Decode(caKeyPEM)
	if caBlock == nil || keyBlock == nil {
		return errors.New("bad CA pem on disk")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	keyDER, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		// fall back to PKCS#8 (both encodings are tolerated)
		k8, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if e != nil {
			return err
		}
		ec, ok := k8.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("CA key is not an EC key")
		}
		keyDER = ec
	}
	if !caCert.IsCA {
		return errors.New("CA certificate is not a CA")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{org}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, parsed)
		}
	}
	if len(tmpl.IPAddresses) == 0 {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("::1"))

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, keyDER)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}), 0o600)
}
