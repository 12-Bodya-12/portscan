package portscan

import (
	"fmt"
	"math/bits"
)

const (
	minPort = 1
	maxPort = 65535
)

type portRange struct {
	from int
	to   int
}

// PortSpec описывает набор TCP-портов для сканирования.
// Валидация выполняется в Scanner.Scan до запуска сетевых операций.
type PortSpec struct {
	singles []int
	ranges  []portRange
	nested  []PortSpec
}

// Ports создаёт спецификацию из списка отдельных портов.
func Ports(ports ...int) PortSpec {
	cp := make([]int, len(ports))
	copy(cp, ports)
	return PortSpec{singles: cp}
}

// Range создаёт спецификацию для включительного диапазона портов [from, to].
func Range(from, to int) PortSpec {
	return PortSpec{
		ranges: []portRange{{from: from, to: to}},
	}
}

// Combine объединяет несколько спецификаций портов в одну.
func Combine(specs ...PortSpec) PortSpec {
	cp := make([]PortSpec, len(specs))
	copy(cp, specs)
	return PortSpec{nested: cp}
}

// portSet хранит дедуплицированные порты 1..65535 в битовом массиве (8 КБ).
type portSet struct {
	bits  [1024]uint64
	count int
}

func (ps *portSet) add(p uint16) {
	idx := p >> 6
	mask := uint64(1) << (p & 63)
	if ps.bits[idx]&mask == 0 {
		ps.bits[idx] |= mask
		ps.count++
	}
}

func (ps *portSet) forEach(fn func(port uint16) bool) {
	for i, word := range ps.bits {
		for word != 0 {
			tz := bits.TrailingZeros64(word)
			if !fn(uint16(i*64 + tz)) {
				return
			}
			word &= word - 1
		}
	}
}

func compilePorts(specs []PortSpec) (portSet, error) {
	var ps portSet
	for _, spec := range specs {
		if err := applyPortSpec(&ps, spec); err != nil {
			return portSet{}, err
		}
	}
	if ps.count == 0 {
		return portSet{}, ErrEmptyPorts
	}
	return ps, nil
}

func applyPortSpec(ps *portSet, spec PortSpec) error {
	for _, p := range spec.singles {
		if p < minPort || p > maxPort {
			return fmt.Errorf("%w: %d", ErrInvalidPort, p)
		}
		ps.add(uint16(p))
	}
	for _, r := range spec.ranges {
		if r.from < minPort || r.from > maxPort {
			return fmt.Errorf("%w: %d", ErrInvalidPort, r.from)
		}
		if r.to < minPort || r.to > maxPort {
			return fmt.Errorf("%w: %d", ErrInvalidPort, r.to)
		}
		if r.from > r.to {
			return fmt.Errorf("%w: %d-%d", ErrInvalidPortRange, r.from, r.to)
		}
		for p := r.from; p <= r.to; p++ {
			ps.add(uint16(p))
		}
	}
	for _, sub := range spec.nested {
		if err := applyPortSpec(ps, sub); err != nil {
			return err
		}
	}
	return nil
}
