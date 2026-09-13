package confkit

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOptionsFromEnv_defaults(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	t.Setenv("SERVICE_NAME", "chat")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_ROLE_ID", "role-abc")
	os.Unsetenv("VAULT_SECRET_ID_FILE")
	os.Unsetenv("CONFKIT_TIMEOUT")
	os.Unsetenv("CONFKIT_PREFIX")

	opts, err := OptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opts.Prefix != "" {
		t.Fatalf("Prefix=%q, want empty", opts.Prefix)
	}
	if opts.SecretIDFile != defaultSecretIDFile {
		t.Fatalf("SecretIDFile=%q, want %q", opts.SecretIDFile, defaultSecretIDFile)
	}
	if opts.Timeout != defaultTimeout {
		t.Fatalf("Timeout=%v, want %v", opts.Timeout, defaultTimeout)
	}
	if opts.Retry.Base != defaultRetryBase || opts.Retry.Multiplier != defaultRetryMult || opts.Retry.Cap != defaultRetryCap {
		t.Fatalf("unexpected Retry: %+v", opts.Retry)
	}
	if opts.Logger == nil {
		t.Fatal("Logger is nil")
	}
}

func TestOptionsFromEnv_missingReportedTogether(t *testing.T) {
	os.Unsetenv("APP_ENV")
	os.Unsetenv("SERVICE_NAME")
	os.Unsetenv("VAULT_ADDR")
	os.Unsetenv("VAULT_ROLE_ID")

	_, err := OptionsFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("want ErrMissingConfig, got %v", err)
	}
	msg := err.Error()
	for _, name := range []string{"APP_ENV", "SERVICE_NAME", "VAULT_ADDR", "VAULT_ROLE_ID"} {
		if !strings.Contains(msg, name) {
			t.Errorf("error %q missing %s", msg, name)
		}
	}
}

func TestOptionsFromEnv_localSkipsVaultVars(t *testing.T) {
	t.Setenv("APP_ENV", "local")
	t.Setenv("SERVICE_NAME", "chat")
	os.Unsetenv("VAULT_ADDR")
	os.Unsetenv("VAULT_ROLE_ID")

	opts, err := OptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opts.Env != "local" || opts.Service != "chat" {
		t.Fatalf("unexpected opts: %+v", opts)
	}
}

func TestOptionsFromEnv_customTimeoutAndSecretFile(t *testing.T) {
	t.Setenv("APP_ENV", "staging")
	t.Setenv("SERVICE_NAME", "api")
	t.Setenv("VAULT_ADDR", "https://vault.example")
	t.Setenv("VAULT_ROLE_ID", "r1")
	t.Setenv("VAULT_SECRET_ID_FILE", "/tmp/sid")
	t.Setenv("CONFKIT_TIMEOUT", "15s")

	opts, err := OptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opts.SecretIDFile != "/tmp/sid" {
		t.Fatalf("SecretIDFile=%q", opts.SecretIDFile)
	}
	if opts.Timeout != 15*time.Second {
		t.Fatalf("Timeout=%v", opts.Timeout)
	}
}

func TestWithDefaults(t *testing.T) {
	opts := Options{}.withDefaults()
	if opts.SecretIDFile != defaultSecretIDFile {
		t.Fatalf("SecretIDFile=%q", opts.SecretIDFile)
	}
	if opts.KVMount != defaultKVMount {
		t.Fatalf("KVMount=%q", opts.KVMount)
	}
	if opts.Timeout != defaultTimeout {
		t.Fatalf("Timeout=%v", opts.Timeout)
	}
	if opts.Retry.Base != defaultRetryBase {
		t.Fatalf("Retry.Base=%v", opts.Retry.Base)
	}
	if opts.Logger == nil {
		t.Fatal("Logger nil")
	}
}

func TestOptionsFromEnv_kvMount(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	t.Setenv("SERVICE_NAME", "chat")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_ROLE_ID", "role")
	t.Setenv("CONFKIT_KV_MOUNT", "secret")
	opts, err := OptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opts.KVMount != "secret" {
		t.Fatalf("KVMount=%q", opts.KVMount)
	}
}

func TestOptionsFromEnv_prefix(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	t.Setenv("SERVICE_NAME", "chat")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_ROLE_ID", "role")
	t.Setenv("CONFKIT_PREFIX", "messenger")
	opts, err := OptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opts.Prefix != "messenger" {
		t.Fatalf("Prefix=%q", opts.Prefix)
	}
}
