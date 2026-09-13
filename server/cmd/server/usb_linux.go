//go:build linux

package main

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// removableDev matches devices that in practice are removable flash media:
// SATA/SD USB sticks (/dev/sd*), SD/MMC cards (/dev/mmcblk*) and LUKS/DM
// maps over them (/dev/mapper/*). Fixed network mounts and tmpfs are skipped.
var removableDev = regexp.MustCompile(`^/dev/(sd[a-z]+\d*|mmcblk\d+(p\d+)?|mapper/)`)

// removableMounts scans /proc/mounts and returns mount points of removable
// storage devices (USB flash drives, SD cards) currently mounted.
func defaultRemovableMounts() []string {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		dev, mount := fields[0], fields[1]
		// Synthetic /dev/root may alias a real disk; skip tmpfs/proc/sys.
		if !removableDev.MatchString(dev) {
			continue
		}
		if strings.HasPrefix(mount, "/proc") || strings.HasPrefix(mount, "/sys") {
			continue
		}
		out = append(out, mount)
	}
	return out
}
