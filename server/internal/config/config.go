package config

import "strings"

// NormalizeAddr turns a port expression into a listen address.
func NormalizeAddr(addr string) string {
	if addr == "" {
		return ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "127.0.0.1:") {
		return addr
	}
	// bare port like "8080"
	return ":" + addr
}
