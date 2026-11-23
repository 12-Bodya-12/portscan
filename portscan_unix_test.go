//go:build unix

package portscan_test

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/12-Bodya-12/portscan"
)

func TestScan_SyscallErrorClassification(t *testing.T) {
	cases := []struct {
		name      string
		errno     syscall.Errno
		wantState portscan.State
	}{
		{"ECONNREFUSED", syscall.ECONNREFUSED, portscan.StateClosed},
		{"EHOSTUNREACH", syscall.EHOSTUNREACH, portscan.StateUnreachable},
		{"ENETUNREACH", syscall.ENETUNREACH, portscan.StateUnreachable},
		{"EHOSTDOWN", syscall.EHOSTDOWN, portscan.StateUnreachable},
		{"ENETDOWN", syscall.ENETDOWN, portscan.StateUnreachable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opErr := &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: tc.errno},
			}

			scanner, err := portscan.New(
				portscan.WithDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
					return nil, opErr
				})),
			)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			results, err := scanner.Scan(context.Background(), []string{"192.0.2.10"}, portscan.Ports(443))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}

			res := <-results
			if res.State != tc.wantState {
				t.Fatalf("errno %v: expected %s, got %s", tc.errno, tc.wantState, res.State)
			}
		})
	}
}
