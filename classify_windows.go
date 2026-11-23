//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

const (
	wsaENetDown     = syscall.Errno(10050)
	wsaENetUnreach  = syscall.Errno(10051)
	wsaEConnRefused = syscall.Errno(10061)
	wsaEHostDown    = syscall.Errno(10064)
	wsaEHostUnreach = syscall.Errno(10065)
)

func isConnRefused(err error) bool {
	return errors.Is(err, wsaEConnRefused)
}

func isUnreachable(err error) bool {
	return errors.Is(err, wsaEHostUnreach) ||
		errors.Is(err, wsaENetUnreach) ||
		errors.Is(err, wsaEHostDown) ||
		errors.Is(err, wsaENetDown)
}
