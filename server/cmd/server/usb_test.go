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

func TestResolveRunKey(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("explicit -key wins", func(t *testing.T) {
		p, err := resolveRunKey(data, "/abs/path/usb/pp.key", true)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if p != "/abs/path/usb/pp.key" {
			t.Fatalf("expected explicit key, got %s", p)
		}
	})

	t.Run("first run: local key next to data", func(t *testing.T) {
		p, err := resolveRunKey(data, "", false)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if want := filepath.Join(data, usbKeyFileName); p != want {
			t.Fatalf("expected %s, got %s", want, p)
		}
	})

	t.Run("reuses local key next to data", func(t *testing.T) {
		local := filepath.Join(data, usbKeyFileName)
		if err := os.WriteFile(local, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := resolveRunKey(data, "", true)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if p != local {
			t.Fatalf("expected %s, got %s", local, p)
		}
	})

	t.Run("no local key, vault present -> USB fallback", func(t *testing.T) {
		if err := os.Remove(filepath.Join(data, usbKeyFileName)); err != nil {
			t.Fatal(err)
		}
		usb := filepath.Join(t.TempDir(), "usb")
		if err := os.MkdirAll(usb, 0o700); err != nil {
			t.Fatal(err)
		}
		existing := filepath.Join(usb, usbKeyFileName)
		if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		prev := removableMounts
		defer func() { removableMounts = prev }()
		removableMounts = func() []string { return []string{usb} }

		p, err := resolveRunKey(data, "", true)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if p != existing {
			t.Fatalf("expected %s, got %s", existing, p)
		}
	})

	t.Run("no local key, no media -> friendly error", func(t *testing.T) {
		prev := removableMounts
		defer func() { removableMounts = prev }()
		removableMounts = func() []string { return nil }
		if _, err := resolveRunKey(data, "", true); err == nil {
			t.Fatal("expected a friendly error")
		}
	})
}
