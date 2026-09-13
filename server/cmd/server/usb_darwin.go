//go:build darwin

package main

import "os"

// removableMounts returns volumes mounted under /Volumes. macOS mounts every
// USB flash drive, SD card and external disk there, so each entry is a
// candidate for the master key; the key file name selects the right one.
func defaultRemovableMounts() []string {
	entries, err := os.ReadDir("/Volumes")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if len(name) == 0 || name[0] == '.' {
			continue
		}
		out = append(out, "/Volumes/"+name)
	}
	return out
}
