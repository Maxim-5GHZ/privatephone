package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The on-disk vault is a single blob: [ 12-byte AES-GCM nonce | ciphertext ].
// The plaintext inside is a raw SQLite file snapshot.

const vaultName = "vault.db"

func seal(blobPath string, key, plain []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	out := make([]byte, 0, aead.NonceSize()+len(plain)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, nil)

	tmp := blobPath + ".part"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, blobPath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// unseal returns nil, nil when no vault exists yet (first run).
func unseal(blobPath string, key []byte) ([]byte, error) {
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, errors.New("vault corrupt: too short")
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("vault decrypt failed (wrong master key, tampering, or corruption): %w", err)
	}
	return plain, nil
}

func sealPath(dataDir string) string {
	return filepath.Join(dataDir, vaultName)
}
