package confkit

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Sentinel errors for callers to inspect with errors.Is.
var (
	ErrSealed             = errors.New("vault sealed")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrMissingConfig      = errors.New("missing config")
	ErrTimeout            = errors.New("timeout")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrAuthNotMounted     = errors.New("approle auth not mounted")
)

// classify maps an underlying failure to a sentinel and whether it is
// safe to retry. The returned error wraps the original so both the
// sentinel and the cause remain inspectable via errors.Is / errors.As.
func classify(err error) (error, bool) {
	if err == nil {
		return nil, false
	}

	if errors.Is(err, ErrSealed) ||
		errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrMissingConfig) ||
		errors.Is(err, ErrTimeout) ||
		errors.Is(err, ErrPermissionDenied) ||
		errors.Is(err, ErrAuthNotMounted) {
		return err, isRetryableSentinel(err)
	}

	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		return classifyStatus(respErr.StatusCode, err)
	}

	// Connection / DNS / timeout style failures are retryable.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return fmt.Errorf("%w", err), true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%w", err), true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w", err), true
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "temporary failure") ||
		strings.Contains(msg, "network is unreachable") {
		return fmt.Errorf("%w", err), true
	}

	// Unknown errors: fail fast rather than hot-loop.
	return fmt.Errorf("%w", err), false
}

func classifyStatus(code int, err error) (error, bool) {
	switch {
	case code == 400:
		return fmt.Errorf("%w: %w", ErrInvalidCredentials, err), false
	case code == 403:
		return fmt.Errorf("%w: %w", ErrPermissionDenied, err), false
	case code == 404:
		return fmt.Errorf("%w: %w", ErrAuthNotMounted, err), false
	case code == 503:
		// Vault returns 503 when sealed or not yet initialized.
		return fmt.Errorf("%w: %w", ErrSealed, err), true
	case code == 429 || code >= 500:
		return fmt.Errorf("%w", err), true
	default:
		return fmt.Errorf("%w", err), false
	}
}

func isRetryableSentinel(err error) bool {
	return errors.Is(err, ErrSealed)
}
