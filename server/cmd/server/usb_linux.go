//go:build linux

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// sysBlockDir, devDir and procMountsPath are swappable so tests can simulate
// /sys, /dev and /proc/mounts deterministically.
var (
	sysBlockDir    = "/sys/block"
	devDir         = "/dev"
	procMountsPath = "/proc/mounts"
)

// blockDevPattern matches block devices we consider for the removable check.
// Internal SATA disks are /dev/sd* too — the removable flag in /sys/block is
// what separates a USB stick from an internal disk.
var blockDevPattern = regexp.MustCompile(`^/dev/(sd[a-z]+\d*|mmcblk\d+(p\d+)?|dm-\d+)$`)

var mapperDevPattern = regexp.MustCompile(`^/dev/mapper/`)

// defaultRemovableMounts scans procMountsPath and returns mount points of
// removable storage devices, i.e. block devices whose base reports
// removable=1 in /sys/block. Internal SATA disks (e.g. a second disk holding a
// different OS) report removable=0 and are never treated as USB media.
func defaultRemovableMounts() []string {
	f, err := os.Open(procMountsPath)
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
		if !blockDevPattern.MatchString(dev) && !mapperDevPattern.MatchString(dev) {
			continue
		}
		if strings.HasPrefix(mount, "/proc") || strings.HasPrefix(mount, "/sys") {
			continue
		}
		if !isRemovableDevice(dev) {
			continue
		}
		out = append(out, mount)
	}
	return out
}

// isRemovableDevice decides whether a /dev path is a physically removable
// medium, using the kernel's removable flag. For device-mapper targets (LUKS
// on a stick) it descends into /sys/block/dm-*/slaves and requires at least
// one removable underlying device.
func isRemovableDevice(dev string) bool {
	rel := strings.TrimPrefix(dev, "/dev/")
	if strings.HasPrefix(rel, "mapper/") {
		return dmHasRemovableSlave(rel)
	}
	return sysfsRemovable(blockBase(rel))
}

// blockBase maps a device name to its kernel base device: sda1 -> sda,
// mmcblk0p1 -> mmcblk0, dm-3 -> dm-3.
func blockBase(name string) string {
	if strings.HasPrefix(name, "mmcblk") {
		if i := strings.IndexByte(name, 'p'); i >= 0 {
			return name[:i]
		}
		return name
	}
	if strings.HasPrefix(name, "dm-") {
		return name
	}
	return strings.TrimRight(name, "0123456789")
}

// sysfsRemovable reports /sys/block/<base>/removable == "1".
func sysfsRemovable(base string) bool {
	data, err := os.ReadFile(filepath.Join(sysBlockDir, base, "removable"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// dmHasRemovableSlave follows /dev/mapper/<name> to its /dev/dm-X node, then
// checks every entry under /sys/block/dm-X/slaves for a removable base device.
func dmHasRemovableSlave(mapperRel string) bool {
	target, err := os.Readlink(filepath.Join(devDir, mapperRel))
	if err != nil {
		return false
	}
	base := blockBase(filepath.Base(target))
	entries, err := os.ReadDir(filepath.Join(sysBlockDir, base, "slaves"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if sysfsRemovable(e.Name()) {
			return true
		}
	}
	return false
}
