package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"privatephone/server/internal/crypto"
)

func TestHalvesLifecycleFirstRunThenRestart(t *testing.T) {
	data, usbs := setupUsbs(t, 2)

	// first run: resolver picks a free stick, CreateHalves materializes the key
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 2 {
			t.Fatalf("expected both sticks as create candidates, got %v", opts)
		}
		return 1, nil // usb2
	})
	src, err := resolveKeySource("", data, false, true)
	if err != nil {
		t.Fatalf("resolve (first run): %v", err)
	}
	if want := filepath.Join(usbs[1], usbKeyFileName); src.usbHalf != want {
		t.Fatalf("expected usb half %s, got %s", want, src.usbHalf)
	}
	mk1, err := crypto.CreateHalves(src.localHalf, src.usbHalf)
	if err != nil {
		t.Fatal(err)
	}
	key1 := mk1.Bytes()
	mk1.Destroy()

	// restart: the only stick that carries the key is proposed and recombined
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 1 || opts[0] != usbs[1] {
			t.Fatalf("expected usb2 to be proposed for reuse, got %v", opts)
		}
		return 0, nil
	})
	src2, err := resolveKeySource("", data, true, false)
	if err != nil {
		t.Fatalf("resolve (restart): %v", err)
	}
	mk2, err := crypto.KeyFromHalves(src2.localHalf, src2.usbHalf)
	if err != nil {
		t.Fatal(err)
	}
	defer mk2.Destroy()
	if !bytes.Equal(key1, mk2.Bytes()) {
		t.Fatal("recombined key must match the one created on first run")
	}
}

// withUsbs sets up a temp "media root" with n USB mounts and swaps
// removableMounts/confirmStick for the duration of the test.
func setupUsbs(t *testing.T, n int) (data string, usbs []string) {
	t.Helper()
	root := t.TempDir()
	data = filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		m := filepath.Join(root, "usb"+string(rune('1'+i)))
		if err := os.MkdirAll(m, 0o700); err != nil {
			t.Fatal(err)
		}
		usbs = append(usbs, m)
	}
	prev := removableMounts
	t.Cleanup(func() { removableMounts = prev })
	removableMounts = func() []string { return usbs }
	return data, usbs
}

// confirmAuto makes the choice hook non-interactive (auto/headless path).
func withConfirm(t *testing.T, fn func(string, []string) (int, error)) {
	t.Helper()
	prev := confirmStick
	t.Cleanup(func() { confirmStick = prev })
	confirmStick = fn
}

func TestResolveKeySourceExplicitKeyWins(t *testing.T) {
	data, _ := setupUsbs(t, 0)
	src, err := resolveKeySource("/abs/path/pp.key", data, true, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src.explicit != "/abs/path/pp.key" {
		t.Fatalf("explicit key must win, got %+v", src)
	}
}

func TestResolveKeySourceErrors(t *testing.T) {
	t.Run("no media, vault present, first-run causes hint", func(t *testing.T) {
		data, _ := setupUsbs(t, 0)
		localHalf(t, data)
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, true, false); err == nil || !strings.Contains(err.Error(), "USB") {
			t.Fatalf("expected a friendly USB error, got %v", err)
		}
	})
	t.Run("no media at all on first run", func(t *testing.T) {
		data, _ := setupUsbs(t, 0)
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, false, true); err == nil || !strings.Contains(err.Error(), "USB") {
			t.Fatalf("expected a friendly USB error, got %v", err)
		}
	})
	t.Run("local half missing and not first run", func(t *testing.T) {
		data, usbs := setupUsbs(t, 1)
		_ = usbs
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, true, false); err == nil || !strings.Contains(err.Error(), "pp.local") {
			t.Fatalf("expected a missing-local-half error, got %v", err)
		}
	})
}

func key(t *testing.T, m string) string {
	t.Helper()
	p := filepath.Join(m, usbKeyFileName)
	if err := os.WriteFile(p, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// localHalf writes the local half next to the data dir (present on an
// already-initialized node).
func localHalf(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(data, localKeyFileName)
	if err := os.WriteFile(p, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveKeySourceReusesUsbHalf(t *testing.T) {
	data, usbs := setupUsbs(t, 2)
	localHalf(t, data)
	key(t, usbs[1])
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 1 || opts[0] != usbs[1] {
			t.Fatalf("expected single stick %s to be proposed, got %v", usbs[1], opts)
		}
		return 0, nil
	})
	src, err := resolveKeySource("", data, true, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := filepath.Join(usbs[1], usbKeyFileName); src.usbHalf != want {
		t.Fatalf("expected %s, got %s", want, src.usbHalf)
	}
	if src.localHalf != filepath.Join(data, localKeyFileName) {
		t.Fatalf("unexpected local half: %s", src.localHalf)
	}
}

func TestResolveKeySourceInteractivePick(t *testing.T) {
	data, usbs := setupUsbs(t, 3)
	localHalf(t, data)
	key(t, usbs[0])
	key(t, usbs[1])
	key(t, usbs[2])
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 3 {
			t.Fatalf("expected 3 sticks to be offered, got %v", opts)
		}
		return 2, nil // picks the third
	})
	src, err := resolveKeySource("", data, true, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := filepath.Join(usbs[2], usbKeyFileName); src.usbHalf != want {
		t.Fatalf("expected %s, got %s", want, src.usbHalf)
	}
}

func TestResolveKeySourceFirstRunCreatesOnFreeStick(t *testing.T) {
	data, usbs := setupUsbs(t, 2)
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 2 {
			t.Fatalf("expected both free sticks to be offered, got %v", opts)
		}
		return 1, nil // picks the second
	})
	src, err := resolveKeySource("", data, false, true)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := filepath.Join(usbs[1], usbKeyFileName); src.usbHalf != want {
		t.Fatalf("expected %s, got %s", want, src.usbHalf)
	}
	// no key file created yet — the caller (CreateHalves) creates it
	if _, err := os.Stat(src.usbHalf); !os.IsNotExist(err) {
		t.Fatal("USB half must not be created by the resolver alone")
	}
}

func TestDefaultConfirmStickHeadless(t *testing.T) {
	prev := stdinIsTTY
	t.Cleanup(func() { stdinIsTTY = prev })
	stdinIsTTY = func() bool { return false }

	if i, err := defaultConfirmStick("q", []string{"/mnt/usb"}); err != nil || i != 0 {
		t.Fatalf("single stick must auto-select, got %d err %v", i, err)
	}
	if _, err := defaultConfirmStick("q", []string{"/mnt/a", "/mnt/b"}); err == nil {
		t.Fatal("several sticks in headless mode must require -key")
	}
}

func TestMountsWithKey(t *testing.T) {
	data, usbs := setupUsbs(t, 3)
	key(t, usbs[1])
	got := mountsWithKey()
	if len(got) != 1 || got[0] != usbs[1] {
		t.Fatalf("expected only usb2 to carry the key, got %v", got)
	}
	_ = data
}

func TestFirstLANIPv4ReturnsValidAddress(t *testing.T) {
	ip := firstLANIPv4()
	if ip == "" || !strings.Contains(ip, ".") {
		t.Fatalf("unexpected IP: %q", ip)
	}
}
