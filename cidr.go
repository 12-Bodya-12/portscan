package portscan

import (
	"fmt"
	"net/netip"
)

const maxCIDRHostBits = 16 // максимум 65536 адресов

// ExpandCIDR разворачивает CIDR-префикс (IPv4/IPv6) в список IP-адресов.
// Для IPv4-подсетей с маской <= /30 исключаются адрес сети и broadcast-адрес.
// Для /31, /32 и IPv6 возвращаются все адреса диапазона.
func ExpandCIDR(cidr string) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHost, err)
	}

	prefix = prefix.Masked()
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits > maxCIDRHostBits {
		return nil, fmt.Errorf("%w: %s", ErrCIDRTooLarge, cidr)
	}

	total := 1 << hostBits
	skipNetworkAndBroadcast := prefix.Addr().Is4() && prefix.Bits() <= 30

	capHint := total
	if skipNetworkAndBroadcast {
		capHint -= 2
	}
	hosts := make([]string, 0, capHint)

	i := 0
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		if skipNetworkAndBroadcast && (i == 0 || i == total-1) {
			i++
			continue
		}
		hosts = append(hosts, addr.String())
		i++
	}

	return hosts, nil
}
