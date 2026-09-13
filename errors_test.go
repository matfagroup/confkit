package confkit

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestClassify_statusCodes(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantSent  error
		retryable bool
	}{
		{
			name:      "400 invalid credentials",
			err:       &api.ResponseError{StatusCode: 400, Errors: []string{"invalid role or secret ID"}},
			wantSent:  ErrInvalidCredentials,
			retryable: false,
		},
		{
			name:      "403 permission denied",
			err:       &api.ResponseError{StatusCode: 403, Errors: []string{"permission denied"}},
			wantSent:  ErrPermissionDenied,
			retryable: false,
		},
		{
			name:      "404 auth not mounted",
			err:       &api.ResponseError{StatusCode: 404, Errors: []string{"no handler"}},
			wantSent:  ErrAuthNotMounted,
			retryable: false,
		},
		{
			name:      "503 sealed",
			err:       &api.ResponseError{StatusCode: 503, Errors: []string{"Vault is sealed"}},
			wantSent:  ErrSealed,
			retryable: true,
		},
		{
			name:      "429 retryable",
			err:       &api.ResponseError{StatusCode: 429, Errors: []string{"slow down"}},
			wantSent:  nil,
			retryable: true,
		},
		{
			name:      "500 retryable",
			err:       &api.ResponseError{StatusCode: 500, Errors: []string{"internal"}},
			wantSent:  nil,
			retryable: true,
		},
		{
			name:      "connection refused",
			err:       &url.Error{Op: "Post", URL: "http://127.0.0.1:8200", Err: errors.New("connection refused")},
			wantSent:  nil,
			retryable: true,
		},
		{
			name:      "dns failure",
			err:       &net.DNSError{Err: "no such host", Name: "vault.invalid", IsNotFound: true},
			wantSent:  nil,
			retryable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retryable := classify(tt.err)
			if retryable != tt.retryable {
				t.Fatalf("retryable=%v, want %v; err=%v", retryable, tt.retryable, got)
			}
			if tt.wantSent != nil && !errors.Is(got, tt.wantSent) {
				t.Fatalf("errors.Is(%v, %v)=false", got, tt.wantSent)
			}
		})
	}
}

func TestClassify_preservesSentinelOnTimeoutWrap(t *testing.T) {
	last := fmt.Errorf("%w: %w", ErrSealed, &api.ResponseError{StatusCode: 503, Errors: []string{"Vault is sealed"}})
	wrapped := fmt.Errorf("%w after %s: %w", ErrTimeout, defaultTimeout, last)

	if !errors.Is(wrapped, ErrTimeout) {
		t.Fatal("expected ErrTimeout")
	}
	if !errors.Is(wrapped, ErrSealed) {
		t.Fatal("expected ErrSealed")
	}
}
