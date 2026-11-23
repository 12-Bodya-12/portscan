package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Dialer абстрагирует установку сетевых соединений (*net.Dialer реализует его).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver абстрагирует разрешение DNS-имён (*net.Resolver реализует его).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolvePolicy определяет поведение, когда DNS-имя возвращает несколько IP.
type ResolvePolicy uint8

const (
	// ResolveAll сканирует все уникальные IP-адреса, возвращённые DNS.
	ResolveAll ResolvePolicy = iota
	// ResolveFirst сканирует только первый валидный IP-адрес, возвращённый DNS.
	ResolveFirst
)

const (
	defaultConcurrency     = 100
	defaultConnectTimeout  = time.Second
	defaultResolveTimeout  = 5 * time.Second
	maxDefaultResultBuffer = 1024
)

type config struct {
	concurrency     int
	connectTimeout  time.Duration
	resolveTimeout  time.Duration
	resolvePolicy   ResolvePolicy
	resultBuffer    int
	resultBufferSet bool
	dialer          Dialer
	resolver        Resolver
}

// Option конфигурирует Scanner при создании через New.
type Option func(*config) error

// WithConcurrency задаёт максимальное число одновременных TCP-подключений на вызов Scan.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n <= 0 {
			return fmt.Errorf("%w: concurrency must be > 0, got %d", ErrInvalidOption, n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout задаёт таймаут одного TCP-подключения.
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: connect timeout must be > 0, got %s", ErrInvalidOption, d)
		}
		c.connectTimeout = d
		return nil
	}
}

// WithResolveTimeout задаёт таймаут DNS-запроса для одного хоста.
func WithResolveTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: resolve timeout must be > 0, got %s", ErrInvalidOption, d)
		}
		c.resolveTimeout = d
		return nil
	}
}

// WithResolvePolicy задаёт политику обработки нескольких IP для одного DNS-имени.
func WithResolvePolicy(p ResolvePolicy) Option {
	return func(c *config) error {
		if p != ResolveAll && p != ResolveFirst {
			return fmt.Errorf("%w: unknown resolve policy %d", ErrInvalidOption, p)
		}
		c.resolvePolicy = p
		return nil
	}
}

// WithResultBuffer задаёт размер буфера выходного канала результатов.
func WithResultBuffer(n int) Option {
	return func(c *config) error {
		if n < 0 {
			return fmt.Errorf("%w: result buffer must be >= 0, got %d", ErrInvalidOption, n)
		}
		c.resultBuffer = n
		c.resultBufferSet = true
		return nil
	}
}

// WithDialer позволяет подменить стандартный *net.Dialer.
func WithDialer(d Dialer) Option {
	return func(c *config) error {
		if d == nil {
			return fmt.Errorf("%w: dialer must not be nil", ErrInvalidOption)
		}
		c.dialer = d
		return nil
	}
}

// WithResolver позволяет подменить стандартный net.DefaultResolver.
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		if r == nil {
			return fmt.Errorf("%w: resolver must not be nil", ErrInvalidOption)
		}
		c.resolver = r
		return nil
	}
}
