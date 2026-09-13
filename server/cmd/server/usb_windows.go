//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// DRIVE_REMOVABLE is the Win32 drive type for removable media (USB flash).
const driveRemovable = 2

// removableMounts enumerates Windows drive letters and keeps only removable
// (USB flash) drives, returned as "X:\" paths.
func defaultRemovableMounts() []string {
	var out []string
	for letter := 'A'; letter <= 'Z'; letter++ {
		root := fmt.Sprintf("%c:\\", letter)
		ut, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		if t := windows.GetDriveType(ut); t == driveRemovable {
			out = append(out, root)
		}
	}
	return out
}
