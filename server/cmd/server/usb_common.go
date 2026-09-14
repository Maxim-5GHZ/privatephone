package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// mountsWithKey returns removable mounts that already carry a USB half (pp.key).
func mountsWithKey() []string {
	var out []string
	for _, m := range removableMounts() {
		if fi, err := os.Stat(filepath.Join(m, usbKeyFileName)); err == nil && fi.Mode().IsRegular() {
			out = append(out, m)
		}
	}
	return out
}

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
	explicit  string // full single-file key (-key), non-empty in rescue/dev mode
	localHalf string // <data>/pp.local
	usbHalf   string // <usb>/pp.key, empty in explicit mode
}

// resolveKeySource picks where the master key lives:
//
//  1. an explicit -key always wins (single full-key file, rescue/dev mode);
//  2. otherwise the two-halves mode: <data>/pp.local + a USB half <usb>/pp.key.
//     Existing USB halves are offered for confirmation (auto-picked headless
//     with a single stick). When createOk is true and no stick carries a key
//     yet, the operator picks a mount where a fresh USB half will be created.
func resolveKeySource(keyFlag, data string, vaultExists, createOk bool) (keySource, error) {
	if keyFlag != "" {
		return keySource{explicit: keyFlag}, nil
	}
	src := keySource{localHalf: filepath.Join(data, localKeyFileName)}
	if _, err := os.Stat(src.localHalf); err != nil {
		if !createOk {
			return src, fmt.Errorf("нет локальной половины мастер-ключа %q (создаётся при первом запуске; либо укажите -key)", src.localHalf)
		}
	}

	stickers := mountsWithKey()
	switch {
	case len(stickers) > 0:
		i, err := confirmStick("Использовать мастер-ключ на USB-носителе:", stickers)
		if err != nil {
			return src, err
		}
		src.usbHalf = filepath.Join(stickers[i], usbKeyFileName)
		return src, nil
	case createOk:
		usbs := removableMounts()
		if len(usbs) == 0 {
			return src, fmt.Errorf("не обнаружено USB-носителей: вставьте и смонтируйте флешку (или укажите -key <путь>)")
		}
		i, err := confirmStick("Создать USB-половину мастер-ключа на носителе:", usbs)
		if err != nil {
			return src, err
		}
		src.usbHalf = filepath.Join(usbs[i], usbKeyFileName)
		return src, nil
	default:
		return src, fmt.Errorf("на USB-носителях не найден ключ %q: вставьте флешку с ключом (или укажите -key <путь>)", usbKeyFileName)
	}
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
func printFirstRun(data, port, scheme, adminOut string, ips []string) {
	host := "127.0.0.1"
	if len(ips) > 0 {
		host = ips[0]
	}
	p := strings.TrimPrefix(port, ":")
	addr := scheme + "://" + host + ":" + p
	fmt.Println()
	fmt.Println("=== ПЕРВЫЙ ЗАПУСК: всё готово, можно работать ===")
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
	fmt.Println("Не вынимайте флешку во время работы: при извлечении сервер затрёт ключ")
	fmt.Println("из памяти и завершится. Потеря флешки ИЛИ локальной половины делает базу")
	fmt.Println("неоткрываемой — храните их раздельно и держите резервный полный ключ в сейфе.")
	fmt.Println()
}
