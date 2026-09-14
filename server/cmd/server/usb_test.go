package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"privatephone/server/internal/crypto"
)

func TestHalvesLifecycleFirstRunThenRestart(t *testing.T) {
	data, usbs := setupUsbs(t, 2)

	// first run: resolver picks a clean stick, CreateHalvesWithID binds the node
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 2 {
			t.Fatalf("expected both sticks as create candidates, got %v", opts)
		}
		return 1, nil // usb2
	})
	src, err := resolveKeySource("", data, false, true, "ТАНЖЕР")
	if err != nil {
		t.Fatalf("resolve (first run): %v", err)
	}
	if want := filepath.Join(usbs[1], usbKeyFileName); src.usbHalf != want {
		t.Fatalf("expected usb half %s, got %s", want, src.usbHalf)
	}
	if src.nodeName != "ТАНЖЕР" || src.nodeID == [16]byte{} {
		t.Fatalf("resolver must assign node identity, got %q %x", src.nodeName, src.nodeID)
	}
	mk1, err := crypto.CreateHalvesWithID(src.localHalf, src.usbHalf, src.nodeID, src.nodeName)
	if err != nil {
		t.Fatal(err)
	}
	key1 := mk1.Bytes()
	mk1.Destroy()

	// restart: the only stick that carries THIS node's key is proposed
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 1 || opts[0] != usbs[1] {
			t.Fatalf("expected usb2 to be proposed for reuse, got %v", opts)
		}
		return 0, nil
	})
	src2, err := resolveKeySource("", data, true, false, "")
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

// withConfirm makes the choice hook non-interactive.
func withConfirm(t *testing.T, fn func(string, []string) (int, error)) {
	t.Helper()
	prev := confirmStick
	t.Cleanup(func() { confirmStick = prev })
	confirmStick = fn
}

// nodeIDFor derives a deterministic nodeID from a name so tests can pair.
func nodeIDFor(name string) [16]byte {
	sum := sha256.Sum256([]byte(name))
	var id [16]byte
	copy(id[:], sum[:16])
	return id
}

// writeNode creates paired halves <data>/pp.local and <m>/pp.key for one node.
func writeNode(t *testing.T, data, m, name string) {
	t.Helper()
	if _, err := crypto.CreateHalvesWithID(filepath.Join(data, localKeyFileName), filepath.Join(m, usbKeyFileName), nodeIDFor(name), name); err != nil {
		t.Fatal(err)
	}
}

// foreignKeyOn puts ONLY a USB half of another node onto mount m (its local
// half stays elsewhere).
func foreignKeyOn(t *testing.T, m, name string) {
	t.Helper()
	dir := t.TempDir()
	ud := filepath.Join(dir, "pp.key")
	if _, err := crypto.CreateHalvesWithID(filepath.Join(dir, "pp.local"), ud, nodeIDFor(name), name); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ud)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m, usbKeyFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// legacyKey writes a raw 32-byte pp.key (pre-nodeID format).
func legacyKey(t *testing.T, m string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(m, usbKeyFileName), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveKeySourceExplicitKeyWins(t *testing.T) {
	data, _ := setupUsbs(t, 0)
	src, err := resolveKeySource("/abs/path/pp.key", data, true, false, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src.explicit != "/abs/path/pp.key" {
		t.Fatalf("explicit key must win, got %+v", src)
	}
}

func TestResolveKeySourceErrors(t *testing.T) {
	t.Run("no media, node deployed", func(t *testing.T) {
		data, _ := setupUsbs(t, 0)
		writeNode(t, data, t.TempDir(), "альфа")
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, true, false, ""); err == nil || !strings.Contains(err.Error(), "USB") {
			t.Fatalf("expected a friendly USB error, got %v", err)
		}
	})
	t.Run("no media at all on first run", func(t *testing.T) {
		data, _ := setupUsbs(t, 0)
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, false, true, ""); err == nil || !strings.Contains(err.Error(), "USB") {
			t.Fatalf("expected a friendly USB error, got %v", err)
		}
	})
	t.Run("local half missing and not first run", func(t *testing.T) {
		data, usbs := setupUsbs(t, 1)
		_ = usbs
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, true, false, ""); err == nil || !strings.Contains(err.Error(), "pp.local") {
			t.Fatalf("expected a missing-local-half error, got %v", err)
		}
	})
	t.Run("legacy local half", func(t *testing.T) {
		data, _ := setupUsbs(t, 1)
		if err := os.WriteFile(filepath.Join(data, localKeyFileName), make([]byte, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveKeySource("", data, true, false, ""); err == nil || !strings.Contains(err.Error(), "формат") {
			t.Fatalf("expected a legacy-format error, got %v", err)
		}
	})
	t.Run("foreign sticks only", func(t *testing.T) {
		data, usbs := setupUsbs(t, 1)
		writeNode(t, data, t.TempDir(), "альфа") // local half on data
		foreignKeyOn(t, usbs[0], "бета")
		if _, err := resolveKeySource("", data, true, false, ""); err == nil ||
			!strings.Contains(err.Error(), "альфа") || !strings.Contains(err.Error(), "бета") {
			t.Fatalf("expected an error naming both nodes, got %v", err)
		}
	})
}

func TestResolveKeySourceReusesUsbHalf(t *testing.T) {
	data, usbs := setupUsbs(t, 2)
	writeNode(t, data, usbs[1], "альфа")
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 1 || opts[0] != usbs[1] {
			t.Fatalf("expected single stick %s to be proposed, got %v", usbs[1], opts)
		}
		return 0, nil
	})
	src, err := resolveKeySource("", data, true, false, "")
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

func TestResolveKeySourceFiltersForeignStick(t *testing.T) {
	data, usbs := setupUsbs(t, 2)
	writeNode(t, data, usbs[0], "альфа")
	foreignKeyOn(t, usbs[1], "бета")
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 1 || opts[0] != usbs[0] {
			t.Fatalf("only the own stick must be offered, got %v", opts)
		}
		return 0, nil
	})
	src, err := resolveKeySource("", data, true, false, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := filepath.Join(usbs[0], usbKeyFileName); src.usbHalf != want {
		t.Fatalf("expected %s, got %s", want, src.usbHalf)
	}
}

func TestResolveKeySourceInteractivePick(t *testing.T) {
	data, usbs := setupUsbs(t, 3)
	writeNode(t, data, usbs[0], "альфа")
	foreignKeyOn(t, usbs[1], "бета")
	foreignKeyOn(t, usbs[2], "бета") // second copy of the foreign node
	withConfirm(t, func(q string, opts []string) (int, error) {
		if len(opts) != 1 || opts[0] != usbs[0] {
			t.Fatalf("multiple foreign copies must not pollute the choice, got %v", opts)
		}
		return 0, nil
	})
	if _, err := resolveKeySource("", data, true, false, ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}
}

func TestResolveKeySourceFirstRunCreateOk(t *testing.T) {
	t.Run("clean sticks offered", func(t *testing.T) {
		data, usbs := setupUsbs(t, 2)
		withConfirm(t, func(q string, opts []string) (int, error) {
			if len(opts) != 2 {
				t.Fatalf("expected both free sticks to be offered, got %v", opts)
			}
			return 1, nil // picks the second
		})
		src, err := resolveKeySource("", data, false, true, "АЛЬФА")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if want := filepath.Join(usbs[1], usbKeyFileName); src.usbHalf != want {
			t.Fatalf("expected %s, got %s", want, src.usbHalf)
		}
		if src.nodeName != "АЛЬФА" || src.nodeID == [16]byte{} {
			t.Fatalf("node identity must be assigned, got %q %x", src.nodeName, src.nodeID)
		}
		if _, err := os.Stat(src.usbHalf); !os.IsNotExist(err) {
			t.Fatal("USB half must not be created by the resolver alone")
		}
	})
	t.Run("autogen node name", func(t *testing.T) {
		data, _ := setupUsbs(t, 1)
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		src, err := resolveKeySource("", data, false, true, "")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !strings.HasPrefix(src.nodeName, "node-") {
			t.Fatalf("expected autogenerated node-<hex> name, got %q", src.nodeName)
		}
	})
	t.Run("busy stick skipped, clean stick offered", func(t *testing.T) {
		data, usbs := setupUsbs(t, 2)
		foreignKeyOn(t, usbs[0], "бета")
		withConfirm(t, func(q string, opts []string) (int, error) {
			if len(opts) != 1 || opts[0] != usbs[1] {
				t.Fatalf("busy stick must not be offered, got %v", opts)
			}
			return 0, nil
		})
		src, err := resolveKeySource("", data, false, true, "")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if want := filepath.Join(usbs[1], usbKeyFileName); src.usbHalf != want {
			t.Fatalf("expected %s, got %s", want, src.usbHalf)
		}
	})
	t.Run("all sticks busy -> hint to insert a clean one", func(t *testing.T) {
		data, usbs := setupUsbs(t, 1)
		foreignKeyOn(t, usbs[0], "бета")
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, false, true, ""); err == nil ||
			!strings.Contains(err.Error(), "чистую флешку") || !strings.Contains(err.Error(), "бета") {
			t.Fatalf("expected 'insert a clean stick' error naming the foreign node, got %v", err)
		}
	})
	t.Run("legacy stick is treated as busy", func(t *testing.T) {
		data, usbs := setupUsbs(t, 1)
		legacyKey(t, usbs[0])
		withConfirm(t, func(string, []string) (int, error) { return 0, nil })
		if _, err := resolveKeySource("", data, false, true, ""); err == nil {
			t.Fatal("a legacy stick must not be overwritten at first run")
		}
	})
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

func TestFirstLANIPv4ReturnsValidAddress(t *testing.T) {
	ip := firstLANIPv4()
	if ip == "" || !strings.Contains(ip, ".") {
		t.Fatalf("unexpected IP: %q", ip)
	}
}
