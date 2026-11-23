package portscan

import (
	"fmt"
	"net/netip"
	"strings"
)

type target struct {
	host string
	ip   netip.Addr // валиден, если цель задана напрямую как IP
}

func parseTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrEmptyHosts
	}

	seen := make(map[string]struct{}, len(hosts))
	targets := make([]target, 0, len(hosts))

	for _, raw := range hosts {
		if strings.TrimSpace(raw) == "" {
			return nil, ErrEmptyHost
		}

		// Пробелы по краям или внутри считаются некорректным адресом.
		if strings.TrimSpace(raw) != raw {
			return nil, fmt.Errorf("%w: %q", ErrInvalidHost, raw)
		}

		if addr, err := netip.ParseAddr(raw); err == nil {
			unmapped := addr.Unmap()
			key := "ip:" + unmapped.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			targets = append(targets, target{
				host: raw,
				ip:   unmapped,
			})
			continue
		}

		if !isValidDNSName(raw) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidHost, raw)
		}

		normalized := strings.ToLower(strings.TrimSuffix(raw, "."))
		key := "dns:" + normalized
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target{
			host: raw,
		})
	}

	return targets, nil
}

// isValidDNSName проверяет синтаксис DNS-имени по RFC 1123 / RFC 3696.
// Отсекает адреса с портами, скобками и псевдо-IP вроде "999.999.999.999".
func isValidDNSName(name string) bool {
	trimmed := strings.TrimSuffix(name, ".")
	if len(trimmed) == 0 || len(trimmed) > 253 {
		return false
	}

	labels := strings.Split(trimmed, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			isDigit := c >= '0' && c <= '9'
			if !isAlpha && !isDigit && c != '-' {
				return false
			}
		}
	}

	// Последняя метка (TLD или одиночное имя) не может состоять только из цифр.
	last := labels[len(labels)-1]
	allDigits := true
	for i := range len(last) {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}
