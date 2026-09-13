package confkit

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

const (
	defaultSecretIDFile = "/run/secrets/vault_secret_id"
	defaultTimeout      = 60 * time.Second
	defaultRetryBase    = 500 * time.Millisecond
	defaultRetryMult    = 2.0
	defaultRetryCap     = 5 * time.Second
)

// RetryPolicy controls exponential backoff between transient failures.
type RetryPolicy struct {
	Base       time.Duration // default 500ms
	Multiplier float64       // default 2
	Cap        time.Duration // default 5s
}

// Options configures Vault AppRole bootstrap.
type Options struct {
	Address      string // VAULT_ADDR
	Env          string // APP_ENV — dev | staging | prod | local
	Service      string // SERVICE_NAME
	RoleID       string // VAULT_ROLE_ID
	SecretIDFile string // path to the file holding the secret_id
	Timeout      time.Duration
	Retry        RetryPolicy
	Logger       *slog.Logger // nil means slog.Default()
}

// OptionsFromEnv builds Options from process environment variables.
// Missing required variables are reported together in one error.
func OptionsFromEnv() (Options, error) {
	env := strings.TrimSpace(os.Getenv("APP_ENV"))
	service := strings.TrimSpace(os.Getenv("SERVICE_NAME"))
	addr := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	roleID := strings.TrimSpace(os.Getenv("VAULT_ROLE_ID"))
	secretFile := strings.TrimSpace(os.Getenv("VAULT_SECRET_ID_FILE"))
	timeoutRaw := strings.TrimSpace(os.Getenv("CONFKIT_TIMEOUT"))

	local := strings.EqualFold(env, "local")

	var missing []string
	if env == "" {
		missing = append(missing, "APP_ENV")
	}
	if service == "" {
		missing = append(missing, "SERVICE_NAME")
	}
	if !local {
		if addr == "" {
			missing = append(missing, "VAULT_ADDR")
		}
		if roleID == "" {
			missing = append(missing, "VAULT_ROLE_ID")
		}
	}
	if len(missing) > 0 {
		return Options{}, fmt.Errorf("%w: %s", ErrMissingConfig, strings.Join(missing, ", "))
	}

	opts := Options{
		Address:      addr,
		Env:          env,
		Service:      service,
		RoleID:       roleID,
		SecretIDFile: secretFile,
		Timeout:      defaultTimeout,
		Retry: RetryPolicy{
			Base:       defaultRetryBase,
			Multiplier: defaultRetryMult,
			Cap:        defaultRetryCap,
		},
		Logger: slog.Default(),
	}

	if timeoutRaw != "" {
		d, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return Options{}, fmt.Errorf("%w: CONFKIT_TIMEOUT: %v", ErrMissingConfig, err)
		}
		opts.Timeout = d
	}

	return opts.withDefaults(), nil
}

// withDefaults fills zero-valued fields so callers who build Options by
// hand get the same sane defaults as OptionsFromEnv.
func (o Options) withDefaults() Options {
	if o.SecretIDFile == "" {
		o.SecretIDFile = defaultSecretIDFile
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Retry.Base <= 0 {
		o.Retry.Base = defaultRetryBase
	}
	if o.Retry.Multiplier <= 0 {
		o.Retry.Multiplier = defaultRetryMult
	}
	if o.Retry.Cap <= 0 {
		o.Retry.Cap = defaultRetryCap
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}
