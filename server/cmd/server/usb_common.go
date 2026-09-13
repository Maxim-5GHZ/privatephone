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
	fmt.Println("  3. на устройствах абонентов один раз импортировать корень")
	fmt.Printf("     %s/ca.crt  (Linux: sudo scripts/install_ca.sh %s/ca.crt; Windows: Import-Certificate)\n", data, data)
	fmt.Printf("     и открывать %s  — без импорта будет предупреждение браузера.\n", addr)
	fmt.Println()
	fmt.Println("Мастер-ключ базы хранится ТОЛЬКО на USB-флешке. Не вынимайте флешку")
	fmt.Println("во время работы: при извлечении сервер затрёт ключ и завершится.")
	fmt.Println()
}
