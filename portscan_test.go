package portscan_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/12-Bodya-12/portscan"
)

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type resolveFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolveFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type noopConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *noopConn) Close() error {
	c.closed.Store(true)
	return nil
}

func TestNew_InvalidOptions(t *testing.T) {
	cases := []struct {
		name string
		opt  portscan.Option
	}{
		{"nil option", nil},
		{"zero concurrency", portscan.WithConcurrency(0)},
		{"negative concurrency", portscan.WithConcurrency(-5)},
		{"zero connect timeout", portscan.WithConnectTimeout(0)},
		{"negative resolve timeout", portscan.WithResolveTimeout(-time.Second)},
		{"negative result buffer", portscan.WithResultBuffer(-1)},
		{"invalid resolve policy", portscan.WithResolvePolicy(portscan.ResolvePolicy(99))},
		{"nil dialer", portscan.WithDialer(nil)},
		{"nil resolver", portscan.WithResolver(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := portscan.New(tc.opt)
			if !errors.Is(err, portscan.ErrInvalidOption) {
				t.Fatalf("expected ErrInvalidOption, got %v", err)
			}
		})
	}
}

func TestScan_Validation(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name    string
		ctx     context.Context
		hosts   []string
		ports   []portscan.PortSpec
		wantErr error
	}{
		{"nil context", nil, []string{"127.0.0.1"}, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrNilContext},
		{"empty hosts", ctx, nil, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrEmptyHosts},
		{"empty host item", ctx, []string{""}, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrEmptyHost},
		{"whitespace host", ctx, []string{"   "}, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrEmptyHost},
		{"host with spaces", ctx, []string{" 127.0.0.1"}, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrInvalidHost},
		{"host with port", ctx, []string{"127.0.0.1:80"}, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrInvalidHost},
		{"invalid ipv4", ctx, []string{"999.999.999.999"}, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrInvalidHost},
		{"invalid dns label", ctx, []string{"-bad.example.com"}, []portscan.PortSpec{portscan.Ports(80)}, portscan.ErrInvalidHost},
		{"empty ports", ctx, []string{"127.0.0.1"}, nil, portscan.ErrEmptyPorts},
		{"empty Ports()", ctx, []string{"127.0.0.1"}, []portscan.PortSpec{portscan.Ports()}, portscan.ErrEmptyPorts},
		{"port zero", ctx, []string{"127.0.0.1"}, []portscan.PortSpec{portscan.Ports(0)}, portscan.ErrInvalidPort},
		{"port too high", ctx, []string{"127.0.0.1"}, []portscan.PortSpec{portscan.Ports(65536)}, portscan.ErrInvalidPort},
		{"negative port", ctx, []string{"127.0.0.1"}, []portscan.PortSpec{portscan.Ports(-1)}, portscan.ErrInvalidPort},
		{"reverse range", ctx, []string{"127.0.0.1"}, []portscan.PortSpec{portscan.Range(1000, 1)}, portscan.ErrInvalidPortRange},
		{"range with zero", ctx, []string{"127.0.0.1"}, []portscan.PortSpec{portscan.Range(0, 10)}, portscan.ErrInvalidPort},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scanner.Scan(tc.ctx, tc.hosts, tc.ports...)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestScan_RealLoopbackOpenAndClosed(t *testing.T) {
	openLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen open: %v", err)
	}
	defer openLn.Close()

	go func() {
		for {
			c, err := openLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen closed: %v", err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	openPort := openLn.Addr().(*net.TCPAddr).Port

	scanner, err := portscan.New(
		portscan.WithConcurrency(4),
		portscan.WithConnectTimeout(time.Second),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	results, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1", "127.0.0.1"},
		portscan.Combine(
			portscan.Ports(openPort, closedPort, openPort),
		),
	)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	got := make(map[uint16]portscan.Result)
	count := 0
	for res := range results {
		count++
		got[res.Port] = res
	}

	if count != 2 {
		t.Fatalf("expected 2 deduplicated results, got %d", count)
	}

	if r := got[uint16(openPort)]; r.State != portscan.StateOpen || r.Err != nil {
		t.Fatalf("open port: expected StateOpen/nil err, got %+v", r)
	}
	if r := got[uint16(closedPort)]; r.State != portscan.StateClosed || r.Err == nil {
		t.Fatalf("closed port: expected StateClosed/non-nil err, got %+v", r)
	}
}

func TestScan_IPv6Loopback(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	scanner, err := portscan.New(portscan.WithConnectTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	results, err := scanner.Scan(context.Background(), []string{"::1", "0:0:0:0:0:0:0:1"}, portscan.Ports(port))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var list []portscan.Result
	for res := range results {
		list = append(list, res)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 deduplicated IPv6 result, got %d", len(list))
	}
	if list[0].State != portscan.StateOpen || !list[0].IP.Is6() {
		t.Fatalf("unexpected IPv6 result: %+v", list[0])
	}
}

func TestScan_ClosesOpenedConnection(t *testing.T) {
	conn := &noopConn{}
	scanner, err := portscan.New(
		portscan.WithDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return conn, nil
		})),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Ports(80))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for range results {
	}

	if !conn.closed.Load() {
		t.Fatal("expected opened TCP connection to be closed")
	}
}

func TestScan_TimeoutAndGenericError(t *testing.T) {
	customErr := errors.New("boom")

	scanner, err := portscan.New(
		portscan.WithConnectTimeout(30*time.Millisecond),
		portscan.WithDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "10.0.0.1:80" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, customErr
		})),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	results, err := scanner.Scan(context.Background(), []string{"10.0.0.1"}, portscan.Ports(80, 81))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	got := make(map[uint16]portscan.Result)
	for res := range results {
		got[res.Port] = res
	}

	if got[80].State != portscan.StateTimeout {
		t.Fatalf("port 80: expected StateTimeout, got %s (%v)", got[80].State, got[80].Err)
	}
	if got[81].State != portscan.StateError || !errors.Is(got[81].Err, customErr) {
		t.Fatalf("port 81: expected StateError with customErr, got %+v", got[81])
	}
}

func TestScan_CanceledState(t *testing.T) {
	started := make(chan struct{})
	scanner, err := portscan.New(
		portscan.WithConcurrency(1),
		portscan.WithResultBuffer(1),
		portscan.WithConnectTimeout(5*time.Second),
		portscan.WithDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Ports(80))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	<-started
	cancel()

	res, ok := <-results
	if !ok {
		t.Fatal("expected canceled result before channel close")
	}
	if res.State != portscan.StateCanceled {
		t.Fatalf("expected StateCanceled, got %s (%v)", res.State, res.Err)
	}
	for range results {
	}
}

func TestScan_DNSMultipleIPsAndUnresolvable(t *testing.T) {
	resolver := resolveFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		switch host {
		case "multi.example":
			return []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.0.2.1"),
			}, nil
		case "missing.example":
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		default:
			return nil, errors.New("unexpected host")
		}
	})

	dialer := dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		return &noopConn{}, nil
	})

	t.Run("ResolveAll", func(t *testing.T) {
		scanner, err := portscan.New(
			portscan.WithResolver(resolver),
			portscan.WithDialer(dialer),
			portscan.WithResolvePolicy(portscan.ResolveAll),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		results, err := scanner.Scan(
			context.Background(),
			[]string{"multi.example", "MULTI.EXAMPLE", "missing.example"},
			portscan.Ports(443),
		)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		var openIPs []netip.Addr
		var resolveErrs []portscan.Result
		for res := range results {
			if res.Host == "missing.example" {
				resolveErrs = append(resolveErrs, res)
			} else if res.State == portscan.StateOpen {
				openIPs = append(openIPs, res.IP)
			}
		}

		if len(openIPs) != 2 {
			t.Fatalf("expected 2 unique resolved IPs, got %v", openIPs)
		}
		if len(resolveErrs) != 1 || resolveErrs[0].Port != 0 || !errors.Is(resolveErrs[0].Err, portscan.ErrResolveFailed) {
			t.Fatalf("unexpected resolve error results: %+v", resolveErrs)
		}
	})

	t.Run("ResolveFirst", func(t *testing.T) {
		scanner, err := portscan.New(
			portscan.WithResolver(resolver),
			portscan.WithDialer(dialer),
			portscan.WithResolvePolicy(portscan.ResolveFirst),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		results, err := scanner.Scan(context.Background(), []string{"multi.example"}, portscan.Ports(443))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		var got []portscan.Result
		for res := range results {
			got = append(got, res)
		}
		if len(got) != 1 || got[0].IP != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("expected single first IP 192.0.2.1, got %+v", got)
		}
	})
}

func TestScan_ConcurrencyLimit(t *testing.T) {
	const limit = 5
	var inFlight atomic.Int32
	var maxSeen atomic.Int32

	scanner, err := portscan.New(
		portscan.WithConcurrency(limit),
		portscan.WithDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			cur := inFlight.Add(1)
			for {
				prev := maxSeen.Load()
				if cur <= prev || maxSeen.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
			inFlight.Add(-1)
			return &noopConn{}, nil
		})),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Range(1, 30))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	count := 0
	for range results {
		count++
	}
	if count != 30 {
		t.Fatalf("expected 30 results, got %d", count)
	}
	if peak := maxSeen.Load(); peak > limit || peak < 2 {
		t.Fatalf("expected peak concurrency in [2, %d], got %d", limit, peak)
	}
}

func TestScan_ContextCancellationAndAbandonedConsumer(t *testing.T) {
	var started atomic.Int32
	var active atomic.Int32

	scanner, err := portscan.New(
		portscan.WithConcurrency(8),
		portscan.WithResultBuffer(1),
		portscan.WithConnectTimeout(5*time.Second),
		portscan.WithDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			started.Add(1)
			active.Add(1)
			defer active.Add(-1)
			<-ctx.Done()
			return nil, ctx.Err()
		})),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, err = scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 5000))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()

	deadline = time.Now().Add(time.Second)
	for active.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatalf("expected 0 active dials after cancel, got %d", active.Load())
	}
	if s := started.Load(); s >= 5000 {
		t.Fatalf("expected cancellation to stop scheduling new jobs, started %d", s)
	}
}

func TestScan_SlowConsumerAndScannerReuse(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(4),
		portscan.WithResultBuffer(2),
		portscan.WithDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return &noopConn{}, nil
		})),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			base := workerID*20 + 1
			results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Range(base, base+19))
			if err != nil {
				t.Errorf("Scan failed: %v", err)
				return
			}
			count := 0
			for res := range results {
				if res.State != portscan.StateOpen {
					t.Errorf("expected StateOpen, got %s", res.State)
				}
				time.Sleep(time.Millisecond)
				count++
			}
			if count != 20 {
				t.Errorf("expected 20 results, got %d", count)
			}
		}(g)
	}
	wg.Wait()
}

func TestExpandCIDR(t *testing.T) {
	hosts, err := portscan.ExpandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ExpandCIDR: %v", err)
	}
	if len(hosts) != 2 || hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Fatalf("unexpected /30 hosts: %v", hosts)
	}

	if _, err := portscan.ExpandCIDR("10.0.0.0/8"); !errors.Is(err, portscan.ErrCIDRTooLarge) {
		t.Fatalf("expected ErrCIDRTooLarge, got %v", err)
	}
}
