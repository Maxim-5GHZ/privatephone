package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"privatephone/server/internal/crypto"
)

// usbKeyFileName is the USB half of the master key, looked for on removable
// media (the "USB stick as a key carrier" model).
const usbKeyFileName = "pp.key"

// localKeyFileName is the local half of the master key, kept next to the data
// on the operator's machine. Neither half alone unlocks the vault.
const localKeyFileName = "pp.local"

// exeDataDir returns <dir-of-the-binary>/data — the default node data
// directory. Deploying the binary into a dedicated user folder (e.g.
// ~/privatephone/pp) keeps the data, the local key half and the ciphertext
// together, regardless of the current working directory.
func exeDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "data")
	}
	return filepath.Join(filepath.Dir(exe), "data")
}

// removableMounts is swappable so tests can simulate USB media deterministically.
var removableMounts = defaultRemovableMounts

// confirmStick presents removable mounts to the operator and returns the chosen
// index. Swappable in tests; the default implementation is interactive on a
// terminal and fallback-auto elsewhere.
var confirmStick = defaultConfirmStick

// defaultConfirmStick asks the operator to pick a removable medium (interactive
// terminal mode). Headless (stdin is not a TTY): a single candidate is selected
// automatically with a warning; several candidates produce an error and the
// operator must pass -key explicitly.
func defaultConfirmStick(q string, opts []string) (int, error) {
	if !stdinIsTTY() {
		if len(opts) == 1 {
			fmt.Fprintf(os.Stderr, "носитель выбран автоматически (stdin не терминал): %s\n", opts[0])
			return 0, nil
		}
		return -1, fmt.Errorf("обнаружено несколько USB-носителей; запустите в терминале для выбора или укажите -key <файл>")
	}
	r := bufio.NewReader(os.Stdin)
	if len(opts) == 1 {
		fmt.Printf("%s %s [Y/n] ", q, opts[0])
		s, err := r.ReadString('\n')
		if err != nil {
			return -1, err
		}
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "", "y", "д":
			return 0, nil
		case "n", "н":
			return -1, fmt.Errorf("отменено оператором")
		}
		return 0, nil
	}
	fmt.Println(q)
	for i, m := range opts {
		fmt.Printf("  %d) %s\n", i+1, m)
	}
	fmt.Printf("выберите носитель [1-%d, Enter=1]: ", len(opts))
	s, err := r.ReadString('\n')
	if err != nil {
		return -1, err
	}
	if s = strings.TrimSpace(s); s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > len(opts) {
		return -1, fmt.Errorf("некорректный номер носителя")
	}
	return n - 1, nil
}

// stdinIsTTY reports whether the operator console is interactive. Swappable in
// tests so headless-mode behavior is testable deterministically.
var stdinIsTTY = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// keySource describes where the master key lives for a node run.
type keySource struct {
	explicit  string   // full single-file key (-key), non-empty in rescue/dev mode
	localHalf string   // <data>/pp.local
	usbHalf   string   // <usb>/pp.key, empty in explicit mode
	nodeID    [16]byte // identity of a freshly created node (first-run wizard)
	nodeName  string   // its operator-facing short name ("ТАНЖЕР")
}

// stickKind classifies a half file found on a removable medium.
type stickKind int

const (
	stickOK      stickKind = iota // new format, header parsed
	stickLegacy                   // raw 32-byte half (pre-nodeID format)
	stickCorrupt                  // file exists but fails strict format checks
)

// stickMount is a removable medium already carrying a USB half.
type stickMount struct {
	path string // <mount>/pp.key
	info crypto.HalfInfo
	kind stickKind
}

// scanSticks returns removable mounts that carry a pp.key, with the parsed
// node identity (or a legacy/corrupt classification).
func scanSticks() []stickMount {
	var out []stickMount
	for _, m := range removableMounts() {
		p := filepath.Join(m, usbKeyFileName)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		s := stickMount{path: p}
		info, err := crypto.ReadHalfHeader(p)
		switch {
		case err == nil:
			s.info, s.kind = info, stickOK
		case errors.Is(err, crypto.ErrHalfLegacy):
			s.kind = stickLegacy
		default:
			s.kind = stickCorrupt
		}
		out = append(out, s)
	}
	return out
}

// shortNodeLabel renders a node identity for diagnostics/operator prompts.
func shortNodeLabel(info crypto.HalfInfo) string {
	if info.Name != "" {
		return info.Name
	}
	return "node-" + hex.EncodeToString(info.NodeID[:4])
}

// describeHalfErr renders a half-file error for the operator.
func describeHalfErr(err error) string {
	switch {
	case errors.Is(err, crypto.ErrHalfLegacy):
		return "устаревший формат половины (без идентификатора узла) — пересоздайте узел"
	case errors.Is(err, crypto.ErrHalfCorrupt):
		return "битый файл половины"
	default:
		return err.Error()
	}
}

// stickLabel describes a stick for warnings.
func stickLabel(s stickMount) string {
	switch s.kind {
	case stickOK:
		return fmt.Sprintf("%s — узел %q", s.path, shortNodeLabel(s.info))
	case stickLegacy:
		return fmt.Sprintf("%s — ключ старого формата (без привязки к узлу)", s.path)
	default:
		return fmt.Sprintf("%s — битый файл ключа", s.path)
	}
}

func randomNodeID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("node id: %v", err)
	}
	return id, nil
}

// resolveKeySource picks where the master key lives:
//
//  1. an explicit -key always wins (single full-key file, rescue/dev mode);
//  2. otherwise the two-halves mode: <data>/pp.local + a USB half <usb>/pp.key.
//
// When the local half exists its nodeID is authoritative: only sticks carrying
// the SAME nodeID are offered for confirmation (auto-picked headless with a
// single match), sticks of other nodes are never offered — they are listed as
// warnings, or the resolution fails with their names when none matches. When
// there is no local half yet (createOk), only CLEAN mounts are offered for a
// fresh USB half; a stick that already holds any pp.key is never overwritten.
// nodeName becomes the identity written into the freshly created halves
// (auto-generated node-<hex> when empty).
func resolveKeySource(keyFlag, data string, vaultExists, createOk bool, nodeName string) (keySource, error) {
	src := keySource{localHalf: filepath.Join(data, localKeyFileName)}
	if keyFlag != "" {
		return keySource{explicit: keyFlag}, nil
	}

	localInfo, lerr := crypto.ReadHalfHeader(src.localHalf)
	switch {
	case lerr != nil && os.IsNotExist(lerr):
		if !createOk {
			return src, fmt.Errorf("нет локальной половины мастер-ключа %q (создаётся при первом запуске; либо укажите -key)", src.localHalf)
		}
	case lerr != nil:
		return src, fmt.Errorf("локальная половина %q: %s (либо укажите -key)", src.localHalf, describeHalfErr(lerr))
	}

	sticks := scanSticks()
	if lerr == nil {
		return resolveUsbReuse(src, localInfo, sticks)
	}
	return resolveUsbCreate(src, nodeName, sticks)
}

// resolveUsbReuse offers only the sticks that carry THIS node's USB half.
func resolveUsbReuse(src keySource, localInfo crypto.HalfInfo, sticks []stickMount) (keySource, error) {
	var compat, other []stickMount
	for _, s := range sticks {
		if s.kind == stickOK && s.info.NodeID == localInfo.NodeID {
			compat = append(compat, s)
		} else {
			other = append(other, s)
		}
	}
	if len(compat) == 0 {
		if len(other) > 0 {
			var b strings.Builder
			for _, s := range other {
				b.WriteString("  " + stickLabel(s) + "\n")
			}
			return src, fmt.Errorf("ни одна из вставленных флешек не принадлежит узлу %q:\n%sc  вставьте флешку этого узла (или укажите -key <путь>)",
				shortNodeLabel(localInfo), b.String())
		}
		return src, fmt.Errorf("на USB-носителях не найден ключ %q: вставьте флешку с ключом (или укажите -key <путь>)", usbKeyFileName)
	}
	for _, s := range other {
		fmt.Fprintf(os.Stderr, "  пропускаю: %s (не половина этого узла)\n", stickLabel(s))
	}
	mounts := make([]string, len(compat))
	for i, s := range compat {
		mounts[i] = filepath.Dir(s.path)
	}
	i, err := confirmStick(fmt.Sprintf("Использовать мастер-ключ на USB-носителе (узел %q):", shortNodeLabel(localInfo)), mounts)
	if err != nil {
		return src, err
	}
	src.usbHalf = filepath.Join(mounts[i], usbKeyFileName)
	return src, nil
}

// resolveUsbCreate offers only CLEAN mounts for a fresh USB half; mounts that
// already carry a pp.key (of any node) are skipped with a warning.
func resolveUsbCreate(src keySource, nodeName string, sticks []stickMount) (keySource, error) {
	byPath := make(map[string]stickMount, len(sticks))
	for _, s := range sticks {
		byPath[s.path] = s
	}
	var clean, busy []string
	for _, m := range removableMounts() {
		p := filepath.Join(m, usbKeyFileName)
		if _, ok := byPath[p]; ok {
			busy = append(busy, m)
			continue
		}
		clean = append(clean, m)
	}
	if len(clean) == 0 {
		if len(busy) > 0 {
			var b strings.Builder
			for _, m := range busy {
				b.WriteString("  " + stickLabel(byPath[filepath.Join(m, usbKeyFileName)]) + "\n")
			}
			return src, fmt.Errorf("все вставленные носители заняты ключами:\n%sc  вставьте чистую флешку (или укажите -key <путь>)", b.String())
		}
		return src, fmt.Errorf("не обнаружено USB-носителей: вставьте и смонтируйте флешку (или укажите -key <путь>)")
	}
	for _, m := range busy {
		fmt.Fprintf(os.Stderr, "  пропускаю: %s (перезапись ключа другого узла запрещена)\n", stickLabel(byPath[filepath.Join(m, usbKeyFileName)]))
	}
	i, err := confirmStick("Создать USB-половину мастер-ключа на носителе:", clean)
	if err != nil {
		return src, err
	}
	src.usbHalf = filepath.Join(clean[i], usbKeyFileName)
	id, err := randomNodeID()
	if err != nil {
		return src, err
	}
	src.nodeID = id
	src.nodeName = nodeName
	if src.nodeName == "" {
		src.nodeName = "node-" + hex.EncodeToString(id[:4])
	}
	return src, nil
}

// firstLANIPv4 returns the first up, non-loopback, non-link-local IPv4
// address of this host (used as the TLS SAN in wizard first-run mode).
func firstLANIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				return ip4.String()
			}
		}
	}
	return ""
}

// printFirstRun prints the operator-facing instructions after a wizard
// first-run initialization ("zero flags" starting page).
func printFirstRun(data, port, scheme, adminOut, nodeName string, ips []string) {
	host := "127.0.0.1"
	if len(ips) > 0 {
		host = ips[0]
	}
	p := strings.TrimPrefix(port, ":")
	addr := scheme + "://" + host + ":" + p
	fmt.Println()
	fmt.Println("=== ПЕРВЫЙ ЗАПУСК: всё готово, можно работать ===")
	fmt.Printf("  0. узел:  %s\n", nodeName)
	fmt.Printf("  1. откройте в браузере:  %s\n", addr)
	fmt.Printf("  2. вход оператора:  файл  %s  (позывной  admin)\n", adminOut)
	fmt.Printf("  3. данные узла (база) лежат в папке:  %s\n", data)
	fmt.Println("  4. на устройствах абонентов один раз импортировать корень")
	fmt.Printf("     %s/ca.crt  (Linux: sudo scripts/install_ca.sh %s/ca.crt; Windows: Import-Certificate)\n", data, data)
	fmt.Printf("     и открывать %s  — без импорта будет предупреждение браузера.\n", addr)
	fmt.Println()
	fmt.Printf("Мастер-ключ базы составной из двух половин:\n")
	fmt.Printf("  локальная половина: %s  (на диске машины)\n", filepath.Join(data, localKeyFileName))
	fmt.Println("  USB-половина       на флешке (pp.key)")
	fmt.Printf("Наклейте на флешку и на корпус машины метку  «%s» — флешка другого узла\n", nodeName)
	fmt.Println("не подойдёт и будет отвергнута с указанием её узла.")
	fmt.Println("Не вынимайте флешку во время работы: при извлечении сервер затрёт ключ")
	fmt.Println("из памяти и завершится. Потеря флешки ИЛИ локальной половины делает базу")
	fmt.Println("неоткрываемой — храните их раздельно и держите резервный полный ключ в сейфе.")
	fmt.Println()
}
