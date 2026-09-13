package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsbKeyResolution(t *testing.T) {
	dir := t.TempDir()
	m1 := filepath.Join(dir, "usb1")
	m2 := filepath.Join(dir, "usb2")
	_ = os.MkdirAll(m1, 0o700)
	_ = os.MkdirAll(m2, 0o700)

	prev := removableMounts
	defer func() { removableMounts = prev }()

	t.Run("no mounts -> friendly error", func(t *testing.T) {
		removableMounts = func() []string { return nil }
		if _, err := pickUsbForNewKey(); err == nil || !strings.Contains(err.Error(), "USB") {
			t.Fatalf("expected a friendly USB error, got %v", err)
		}
		if _, err := findExistingUsbKey(); err == nil {
			t.Fatal("expected error when no key exists")
		}
	})

	t.Run("creates key on first free mount", func(t *testing.T) {
		removableMounts = func() []string { return []string{m1, m2} }
		p, err := pickUsbForNewKey()
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if want := filepath.Join(m1, usbKeyFileName); p != want {
			t.Fatalf("expected %s, got %s", want, p)
		}
	})

	t.Run("reuses existing key", func(t *testing.T) {
		existing := filepath.Join(m2, usbKeyFileName)
		if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		removableMounts = func() []string { return []string{m1, m2} }
		p, err := findExistingUsbKey()
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		if p != existing {
			t.Fatalf("expected %s, got %s", existing, p)
		}
		p2, err := pickUsbForNewKey()
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if p2 != existing {
			t.Fatalf("pick must reuse existing key, got %s", p2)
		}
	})

	t.Run("firstLANIPv4 returns a syntactically valid address", func(t *testing.T) {
		ip := firstLANIPv4()
		if ip != "" {
			if !strings.Contains(ip, ".") {
				t.Fatalf("unexpected IP format: %q", ip)
			}
		}
	})
}
