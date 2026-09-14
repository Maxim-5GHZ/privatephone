//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRemovableMountsFiltersInternalDisks(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "sys-block")
	dev := filepath.Join(root, "dev")
	mountsFile := filepath.Join(root, "mounts")

	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// sda = internal SATA (removable=0), sdb = USB stick (removable=1),
	// mmcblk0 = SD card (removable=1).
	write(filepath.Join(sys, "sda", "removable"), "0\n")
	write(filepath.Join(sys, "sdb", "removable"), "1\n")
	write(filepath.Join(sys, "mmcblk0", "removable"), "1\n")
	// LUKS over the internal SATA disk: dm-0 -> slaves/sda (removable=0).
	if err := os.MkdirAll(filepath.Join(sys, "dm-0", "slaves"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(sys, "sda"), filepath.Join(sys, "dm-0", "slaves", "sda"))
	// LUKS over the USB stick: dm-1 -> slaves/sdb (removable=1).
	if err := os.MkdirAll(filepath.Join(sys, "dm-1", "slaves"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(sys, "sdb"), filepath.Join(sys, "dm-1", "slaves", "sdb"))
	_ = os.MkdirAll(dev, 0o700)
	_ = os.MkdirAll(filepath.Join(dev, "mapper"), 0o700)
	_ = os.Symlink("../dm-0", filepath.Join(dev, "mapper", "crypt-sata"))
	_ = os.Symlink("../dm-1", filepath.Join(dev, "mapper", "crypt-stick"))

	mounts := "" +
		"/dev/sda1 /mnt/system ext4 rw 0 0\n" +
		"/dev/sdb1 /media/me/PPKEY vfat rw 0 0\n" +
		"/dev/mmcblk0p1 /media/me/SD ext4 rw 0 0\n" +
		"/dev/mapper/crypt-sata /mnt/luks-sata ext4 rw 0 0\n" +
		"/dev/mapper/crypt-stick /media/me/LUKS ext4 rw 0 0\n" +
		"tmpfs /run tmpfs rw 0 0\n"
	write(mountsFile, mounts)

	prevSys, prevDev, prevMounts := sysBlockDir, devDir, procMountsPath
	defer func() {
		sysBlockDir, devDir, procMountsPath = prevSys, prevDev, prevMounts
	}()
	sysBlockDir, devDir, procMountsPath = sys, dev, mountsFile

	got := defaultRemovableMounts()
	want := []string{"/media/me/PPKEY", "/media/me/SD", "/media/me/LUKS"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestBlockBase(t *testing.T) {
	cases := map[string]string{
		"sda":       "sda",
		"sda1":      "sda",
		"sda12":     "sda",
		"mmcblk0":   "mmcblk0",
		"mmcblk0p1": "mmcblk0",
		"dm-3":      "dm-3",
	}
	for in, want := range cases {
		if got := blockBase(in); got != want {
			t.Fatalf("blockBase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsRemovableDeviceViaSysfs(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "sys-block")
	dev := filepath.Join(root, "dev")
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(sys, "sdc", "removable"), "0\n")
	write(filepath.Join(sys, "sdd", "removable"), "1\n")

	prevSys, prevDev := sysBlockDir, devDir
	defer func() { sysBlockDir, devDir = prevSys, prevDev }()
	sysBlockDir, devDir = sys, dev

	if isRemovableDevice("/dev/sdc") {
		t.Fatal("sdc (removable=0) must not be removable")
	}
	if !isRemovableDevice("/dev/sdd") {
		t.Fatal("sdd (removable=1) must be removable")
	}
	// A device without a sysfs entry is treated as not removable (conservative).
	if isRemovableDevice("/dev/sde1") {
		t.Fatal("missing sysfs entry must not be treated as removable")
	}
}
