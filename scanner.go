package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Result содержит структурированный результат проверки порта (или ошибки DNS при Port == 0).
type Result struct {
	Host     string
	IP       netip.Addr
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

// Scanner выполняет конкурентное TCP Connect-сканирование портов.
// Экземпляр неизменяем после создания и безопасен для повторного и конкурентного использования.
type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
	resolveTimeout time.Duration
	resolvePolicy  ResolvePolicy
	resultBuffer   int
	dialer         Dialer
	resolver       Resolver
}

// New создаёт новый экземпляр Scanner с указанными опциями.
func New(opts ...Option) (*Scanner, error) {
	cfg := config{
		concurrency:    defaultConcurrency,
		connectTimeout: defaultConnectTimeout,
		resolveTimeout: defaultResolveTimeout,
		resolvePolicy:  ResolveAll,
		dialer:         &net.Dialer{},
		resolver:       net.DefaultResolver,
	}

	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option", ErrInvalidOption)
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	resultBuffer := cfg.resultBuffer
	if !cfg.resultBufferSet {
		resultBuffer = min(cfg.concurrency, maxDefaultResultBuffer)
	}

	return &Scanner{
		concurrency:    cfg.concurrency,
		connectTimeout: cfg.connectTimeout,
		resolveTimeout: cfg.resolveTimeout,
		resolvePolicy:  cfg.resolvePolicy,
		resultBuffer:   resultBuffer,
		dialer:         cfg.dialer,
		resolver:       cfg.resolver,
	}, nil
}

type scanJob struct {
	host string
	ip   netip.Addr
	port uint16
}

// Scan запускает асинхронное сканирование указанных хостов и портов.
// Возвращаемый канал закрывается автоматически после завершения всех проверок или отмены ctx.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports ...PortSpec) (<-chan Result, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	targets, err := parseTargets(hosts)
	if err != nil {
		return nil, err
	}

	ps, err := compilePorts(ports)
	if err != nil {
		return nil, err
	}

	// Если контекст уже отменён до старта, не запускаем горутины.
	if ctx.Err() != nil {
		closed := make(chan Result)
		close(closed)
		return closed, nil
	}

	numWorkers := s.workerCount(targets, ps.count)
	jobs := make(chan scanJob)
	results := make(chan Result, s.resultBuffer)

	var workersWG sync.WaitGroup
	for range numWorkers {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				res := s.scanPort(ctx, job)
				if !sendResult(ctx, results, res) {
					return
				}
			}
		}()
	}

	go func() {
		defer close(results)
		defer func() {
			close(jobs)
			workersWG.Wait()
		}()
		s.produceJobs(ctx, targets, &ps, jobs, results)
	}()

	return results, nil
}

func (s *Scanner) workerCount(targets []target, portCount int) int {
	hasDNS := false
	for _, t := range targets {
		if !t.ip.IsValid() {
			hasDNS = true
			break
		}
	}
	if hasDNS {
		return s.concurrency
	}
	// Предотвращаем переполнение int при больших значениях.
	if len(targets) >= s.concurrency || portCount >= s.concurrency {
		return s.concurrency
	}
	total := len(targets) * portCount
	if total < s.concurrency {
		return total
	}
	return s.concurrency
}

func (s *Scanner) produceJobs(
	ctx context.Context,
	targets []target,
	ps *portSet,
	jobs chan<- scanJob,
	results chan<- Result,
) {
	for _, t := range targets {
		if ctx.Err() != nil {
			return
		}

		var ips []netip.Addr
		if t.ip.IsValid() {
			ips = []netip.Addr{t.ip}
		} else {
			var errRes Result
			var ok bool
			ips, errRes, ok = s.resolveHost(ctx, t.host)
			if !ok {
				if !sendResult(ctx, results, errRes) {
					return
				}
				continue
			}
		}

		for _, ip := range ips {
			stopped := false
			ps.forEach(func(port uint16) bool {
				if ctx.Err() != nil {
					stopped = true
					return false
				}
				select {
				case jobs <- scanJob{host: t.host, ip: ip, port: port}:
					return true
				case <-ctx.Done():
					stopped = true
					return false
				}
			})
			if stopped {
				return
			}
		}
	}
}

func (s *Scanner) resolveHost(ctx context.Context, host string) ([]netip.Addr, Result, bool) {
	resolveCtx, cancel := context.WithTimeout(ctx, s.resolveTimeout)
	defer cancel()

	start := time.Now()
	addrs, err := s.resolver.LookupNetIP(resolveCtx, "ip", host)
	dur := time.Since(start)

	if err == nil && len(addrs) == 0 {
		err = ErrResolveFailed
	}
	if err != nil {
		wrapped := err
		if !errors.Is(err, ErrResolveFailed) {
			wrapped = fmt.Errorf("%w: %w", ErrResolveFailed, err)
		}
		return nil, Result{
			Host:     host,
			Port:     0,
			State:    classifyError(ctx, resolveCtx, err),
			Duration: dur,
			Err:      wrapped,
		}, false
	}

	seen := make(map[netip.Addr]struct{}, len(addrs))
	unique := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap()
		if _, exists := seen[a]; exists {
			continue
		}
		seen[a] = struct{}{}
		unique = append(unique, a)
		if s.resolvePolicy == ResolveFirst {
			break
		}
	}

	if len(unique) == 0 {
		return nil, Result{
			Host:     host,
			Port:     0,
			State:    StateError,
			Duration: dur,
			Err:      ErrResolveFailed,
		}, false
	}

	return unique, Result{}, true
}

func (s *Scanner) scanPort(ctx context.Context, job scanJob) Result {
	dialCtx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()

	addr := netip.AddrPortFrom(job.ip, job.port).String()
	start := time.Now()
	conn, err := s.dialer.DialContext(dialCtx, "tcp", addr)
	dur := time.Since(start)

	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return Result{
			Host:     job.host,
			IP:       job.ip,
			Port:     job.port,
			State:    StateOpen,
			Duration: dur,
		}
	}

	return Result{
		Host:     job.host,
		IP:       job.ip,
		Port:     job.port,
		State:    classifyError(ctx, dialCtx, err),
		Duration: dur,
		Err:      err,
	}
}

// sendResult доставляет результат в канал с поддержкой backpressure.
// Если контекст отменён, выполняется неблокирующая попытка записи,
// чтобы избежать утечки горутин при заброшенном канале.
func sendResult(ctx context.Context, ch chan<- Result, res Result) bool {
	if ctx.Err() != nil {
		select {
		case ch <- res:
		default:
		}
		return false
	}
	select {
	case ch <- res:
		return true
	case <-ctx.Done():
		select {
		case ch <- res:
		default:
		}
		return false
	}
}
