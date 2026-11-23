package portscan

import "errors"

var (
	// ErrInvalidOption возвращается при передаче некорректной опции в New.
	ErrInvalidOption = errors.New("portscan: invalid option")
	// ErrNilContext возвращается, если в Scan передан nil context.
	ErrNilContext = errors.New("portscan: nil context")
	// ErrEmptyHosts возвращается, если список хостов пуст.
	ErrEmptyHosts = errors.New("portscan: empty host list")
	// ErrEmptyHost возвращается, если среди целей передана пустая строка.
	ErrEmptyHost = errors.New("portscan: empty host")
	// ErrInvalidHost возвращается при некорректном IP-адресе или DNS-имени.
	ErrInvalidHost = errors.New("portscan: invalid host")
	// ErrEmptyPorts возвращается, если итоговый набор портов пуст.
	ErrEmptyPorts = errors.New("portscan: empty port list")
	// ErrInvalidPort возвращается при номере порта вне диапазона 1..65535.
	ErrInvalidPort = errors.New("portscan: invalid port")
	// ErrInvalidPortRange возвращается при обратном диапазоне портов (from > to).
	ErrInvalidPortRange = errors.New("portscan: invalid port range")
	// ErrResolveFailed оборачивает ошибки DNS-резолвинга хоста.
	ErrResolveFailed = errors.New("portscan: dns resolution failed")
	// ErrCIDRTooLarge возвращается в ExpandCIDR при превышении лимита адресов.
	ErrCIDRTooLarge = errors.New("portscan: cidr prefix exceeds maximum allowed hosts")
)
