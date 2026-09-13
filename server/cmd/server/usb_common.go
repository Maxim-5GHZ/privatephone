package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// usbKeyFileName is the master-key file name looked for on removable media.
const usbKeyFileName = "pp.key"

// exeDataDir returns <dir-of-the-binary>/data — the portable "server on a
// flash" default. Because the data directory (and everything in it) lives
// next to the binary, launching the binary straight off a USB stick works
// regardless of the current working directory.
func exeDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "data")
	}
	return filepath.Join(filepath.Dir(exe), "data")
}

// removableMounts is swappable so tests can simulate USB media deterministically.
var removableMounts = defaultRemovableMounts

// findExistingUsbKey returns the path of an existing master key found on a
// removable USB device, or a friendly error telling the operator to mount one.
func findExistingUsbKey() (string, error) {
	for _, m := range removableMounts() {
		p := filepath.Join(m, usbKeyFileName)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("на USB-носителях не найден файл %q: вставьте и смонтируйте флешку с мастер-ключом (или укажите -key <путь>)", usbKeyFileName)
}

// pickUsbForNewKey returns a path on a removable USB device where a fresh
// master key can be created. Reuses an existing key when present.
func pickUsbForNewKey() (string, error) {
	if p, err := findExistingUsbKey(); err == nil {
		return p, nil
	}
	mounts := removableMounts()
	if len(mounts) == 0 {
		return "", fmt.Errorf("не обнаружено USB-носителей: вставьте флешку и смонтируйте её (или укажите -key <путь>)")
	}
	for _, m := range mounts {
		p := filepath.Join(m, usbKeyFileName)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p, nil
		}
	}
	return filepath.Join(mounts[0], usbKeyFileName), nil
}

// resolveRunKey picks the master-key path for `pp run` in auto (no -key) mode:
//
//  1. an explicit -key flag always wins;
//  2. <data>/pp.key next to the binary (portable "server on a flash"): reuse
//     it if it exists; on first run (no vault yet) it is where the fresh key
//     will be created;
//  3. a vault exists but there is no local key — legacy fallback: search
//     removable USB media;
//  4. otherwise a friendly error telling the operator what to plug in.
func resolveRunKey(data, keyFlag string, vaultExists bool) (string, error) {
	if keyFlag != "" {
		return keyFlag, nil
	}
	local := filepath.Join(data, usbKeyFileName)
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	if !vaultExists {
		return local, nil
	}
	return findExistingUsbKey()
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
	fmt.Println("Мастер-ключ базы хранится ТОЛЬКО на USB-флешке. Не вынимайте флешку")
	fmt.Println("во время работы: при извлечении сервер затрёт ключ и завершится.")
	fmt.Println()
}
