package confkit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// Loader holds an authenticated Vault session created at process startup.
// The next phase adds an Into method for reading secrets into structs.
// There is no exported way to obtain the raw token string.
type Loader struct {
	client  *api.Client
	env     string
	service string
	local   bool
	logger  *slog.Logger
	closed  bool
}

// New authenticates to Vault with AppRole using opts, or returns a local
// loader when Env is "local". The overall Timeout bounds every attempt;
// on expiry the returned error wraps both ErrTimeout and the last
// underlying failure so errors.Is can match either.
func New(ctx context.Context, opts Options) (*Loader, error) {
	opts = opts.withDefaults()

	if opts.Env == "" {
		return nil, fmt.Errorf("%w: Env", ErrMissingConfig)
	}
	if opts.Service == "" {
		return nil, fmt.Errorf("%w: Service", ErrMissingConfig)
	}

	if isLocalEnv(opts.Env) {
		return &Loader{
			env:     opts.Env,
			service: opts.Service,
			local:   true,
			logger:  opts.Logger,
		}, nil
	}

	if opts.Address == "" {
		return nil, fmt.Errorf("%w: Address (VAULT_ADDR)", ErrMissingConfig)
	}
	if opts.RoleID == "" {
		return nil, fmt.Errorf("%w: RoleID (VAULT_ROLE_ID)", ErrMissingConfig)
	}
	if _, err := url.ParseRequestURI(opts.Address); err != nil {
		return nil, fmt.Errorf("%w: invalid VAULT_ADDR %q: %v", ErrMissingConfig, opts.Address, err)
	}

	secretID, err := readSecretID(opts.SecretIDFile, opts.Logger)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(secretID)

	cfg := api.DefaultConfig()
	cfg.Address = opts.Address
	// Disable the client's own retry; we own the retry loop.
	cfg.MaxRetries = 0

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	// api.NewClient silently picks up VAULT_TOKEN from the environment.
	// Clear it so AppRole is always exercised.
	client.ClearToken()

	deadline := time.Now().Add(opts.Timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	var lastErr error

	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("%w after %s: %w", ErrTimeout, opts.Timeout, lastErr)
			}
			return nil, fmt.Errorf("%w after %s: %w", ErrTimeout, opts.Timeout, err)
		}

		token, accessor, ttl, err := loginAppRole(ctx, client, opts.RoleID, string(secretID))
		if err == nil {
			client.SetToken(token)
			opts.Logger.Info("vault login succeeded",
				"address", opts.Address,
				"env", opts.Env,
				"service", opts.Service,
				"accessor", accessor,
				"ttl", ttl.String(),
			)
			return &Loader{
				client:  client,
				env:     opts.Env,
				service: opts.Service,
				local:   false,
				logger:  opts.Logger,
			}, nil
		}

		// Context expiry mid-request must not erase the last real cause
		// (e.g. sealed); callers need errors.Is(err, ErrSealed).
		if ctx.Err() != nil {
			if lastErr == nil {
				lastErr, _ = classify(err)
			}
			return nil, fmt.Errorf("%w after %s: %w", ErrTimeout, opts.Timeout, lastErr)
		}

		classified, retryable := classify(err)
		lastErr = classified

		if !retryable {
			opts.Logger.Error("vault login failed", "err", classified)
			return nil, classified
		}

		backoff := nextBackoff(attempt, opts.Retry, rnd)
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("%w after %s: %w", ErrTimeout, opts.Timeout, lastErr)
		}
		if backoff > remaining {
			backoff = remaining
		}

		opts.Logger.Info("vault login retrying",
			"attempt", attempt+1,
			"backoff", backoff.String(),
			"reason", classified.Error(),
		)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("%w after %s: %w", ErrTimeout, opts.Timeout, lastErr)
		case <-timer.C:
		}
	}
}

func loginAppRole(ctx context.Context, client *api.Client, roleID, secretID string) (token, accessor string, ttl time.Duration, err error) {
	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	secret, err := client.Logical().WriteWithContext(ctx, "auth/approle/login", data)
	if err != nil {
		return "", "", 0, err
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", "", 0, fmt.Errorf("%w: empty login response", ErrInvalidCredentials)
	}
	ttl = time.Duration(secret.Auth.LeaseDuration) * time.Second
	return secret.Auth.ClientToken, secret.Auth.Accessor, ttl, nil
}

func isLocalEnv(env string) bool {
	return strings.EqualFold(env, "local")
}

// Env returns the configured APP_ENV value.
func (l *Loader) Env() string { return l.env }

// Service returns the configured SERVICE_NAME value.
func (l *Loader) Service() string { return l.service }

// IsLocal reports whether this loader skipped Vault entirely.
func (l *Loader) IsLocal() bool { return l.local }

// TokenInfo looks up the current token metadata (accessor, TTL, policies).
// On a local loader it returns (nil, nil) so callers and probe can proceed
// without treating local mode as a failure.
func (l *Loader) TokenInfo(ctx context.Context) (*TokenInfo, error) {
	if l.local {
		return nil, nil
	}
	if l.client == nil || l.closed {
		return nil, fmt.Errorf("loader is closed")
	}
	secret, err := l.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		classified, _ := classify(err)
		return nil, classified
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty token lookup response")
	}

	info := &TokenInfo{}
	if v, ok := secret.Data["accessor"].(string); ok {
		info.Accessor = v
	}
	if v, ok := secret.Data["renewable"].(bool); ok {
		info.Renewable = v
	}
	switch v := secret.Data["ttl"].(type) {
	case int:
		info.TTL = time.Duration(v) * time.Second
	case int64:
		info.TTL = time.Duration(v) * time.Second
	case float64:
		info.TTL = time.Duration(v) * time.Second
	case json.Number:
		n, _ := v.Int64()
		info.TTL = time.Duration(n) * time.Second
	}
	if pols, ok := secret.Data["policies"].([]interface{}); ok {
		for _, p := range pols {
			if s, ok := p.(string); ok {
				info.Policies = append(info.Policies, s)
			}
		}
	}
	return info, nil
}

// RevokeSelf discards the current Vault token. Callers that want clean
// shutdown should call this explicitly before Close. Local loaders are a
// no-op.
func (l *Loader) RevokeSelf(ctx context.Context) error {
	if l.local {
		return nil
	}
	if l.client == nil || l.closed {
		return fmt.Errorf("loader is closed")
	}
	err := l.client.Auth().Token().RevokeSelfWithContext(ctx, "")
	if err != nil {
		classified, _ := classify(err)
		return classified
	}
	l.client.ClearToken()
	return nil
}

// Close releases resources held by the loader. It does not revoke the
// Vault token — call RevokeSelf explicitly for that. Close is idempotent.
func (l *Loader) Close() error {
	if l.closed {
		return nil
	}
	l.closed = true
	l.client = nil
	return nil
}
