//go:build !unix && !windows

package portscan

func isConnRefused(error) bool {
	return false
}

func isUnreachable(error) bool {
	return false
}
