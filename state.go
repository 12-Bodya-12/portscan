package portscan

import (
	"context"
	"errors"
	"net"
	"os"
)

// State описывает итоговое состояние проверки TCP-порта.
type State uint8

const (
	StateOpen State = iota + 1
	StateClosed
	StateTimeout
	StateUnreachable
	StateCanceled
	StateError
)

// String возвращает строковое представление состояния порта.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// classifyError определяет State строго по типам и sentinel-ошибкам,
// без сравнения текстового представления err.Error().
func classifyError(scanCtx, opCtx context.Context, err error) State {
	if errors.Is(err, context.Canceled) || errors.Is(scanCtx.Err(), context.Canceled) {
		return StateCanceled
	}
	if isConnRefused(err) {
		return StateClosed
	}
	if isUnreachable(err) {
		return StateUnreachable
	}
	if isTimeout(opCtx, err) || errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		return StateTimeout
	}
	return StateError
}

func isTimeout(opCtx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if opCtx != nil && errors.Is(opCtx.Err(), context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
