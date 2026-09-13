package confkit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeSecretID(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret_id")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNew_local(t *testing.T) {
	loader, err := New(context.Background(), Options{
		Env:     "local",
		Service: "chat",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer loader.Close()

	if !loader.IsLocal() {
		t.Fatal("expected local")
	}
	info, err := loader.TokenInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Fatalf("expected nil TokenInfo, got %+v", info)
	}
	if err := loader.RevokeSelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := loader.Close(); err != nil {
		t.Fatal(err)
	}
	// Close is idempotent.
	if err := loader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNew_loginSuccess(t *testing.T) {
	var loginHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/approle/login":
			loginHits.Add(1)
			body, _ := io.ReadAll(r.Body)
			var payload map[string]interface{}
			_ = json.Unmarshal(body, &payload)
			if payload["role_id"] != "role-1" || payload["secret_id"] != "secret-1" {
				t.Errorf("unexpected login payload: %s", body)
			}
			// Ambient VAULT_TOKEN must not be used — no Authorization header expected pre-login.
			if auth := r.Header.Get("X-Vault-Token"); auth != "" {
				t.Errorf("login request carried vault token %q", auth)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "tok-abc",
					"accessor":       "acc-abc",
					"lease_duration": 3600,
					"renewable":      true,
					"policies":       []string{"default", "chat"},
				},
			})
		case r.URL.Path == "/v1/auth/token/lookup-self":
			if r.Header.Get("X-Vault-Token") != "tok-abc" {
				http.Error(w, "missing token", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"accessor":  "acc-abc",
					"ttl":       3500,
					"renewable": true,
					"policies":  []string{"default", "chat"},
				},
			})
		case r.URL.Path == "/v1/auth/token/revoke-self":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sid := writeSecretID(t, "secret-1\n")
	loader, err := New(context.Background(), Options{
		Address:      srv.URL,
		Env:          "dev",
		Service:      "chat",
		RoleID:       "role-1",
		SecretIDFile: sid,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer loader.Close()

	if loader.IsLocal() {
		t.Fatal("expected non-local")
	}
	if loginHits.Load() != 1 {
		t.Fatalf("login hits=%d", loginHits.Load())
	}

	info, err := loader.TokenInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Accessor != "acc-abc" {
		t.Fatalf("accessor=%q", info.Accessor)
	}
	if info.TTL != 3500*time.Second {
		t.Fatalf("ttl=%v", info.TTL)
	}
	if !info.Renewable {
		t.Fatal("expected renewable")
	}
	if strings.Join(info.Policies, ",") != "default,chat" {
		t.Fatalf("policies=%v", info.Policies)
	}

	if err := loader.RevokeSelf(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNew_ignoresAmbientVAULT_TOKEN(t *testing.T) {
	var sawAppRole atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			sawAppRole.Store(true)
			if tok := r.Header.Get("X-Vault-Token"); tok != "" {
				t.Errorf("approle login sent ambient token %q", tok)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "from-approle",
					"accessor":       "acc",
					"lease_duration": 60,
					"renewable":      false,
					"policies":       []string{"default"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "ambient-should-be-cleared")

	sid := writeSecretID(t, "secret-1")
	loader, err := New(context.Background(), Options{
		Address:      srv.URL,
		Env:          "dev",
		Service:      "chat",
		RoleID:       "role-1",
		SecretIDFile: sid,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer loader.Close()

	if !sawAppRole.Load() {
		t.Fatal("expected AppRole login")
	}
}

func TestNew_invalidCredentialsFailFast(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["invalid role or secret ID"]}`))
	}))
	defer srv.Close()

	sid := writeSecretID(t, "bad-secret")
	start := time.Now()
	_, err := New(context.Background(), Options{
		Address:      srv.URL,
		Env:          "dev",
		Service:      "chat",
		RoleID:       "wrong-role",
		SecretIDFile: sid,
		Timeout:      30 * time.Second,
		Retry: RetryPolicy{
			Base:       500 * time.Millisecond,
			Multiplier: 2,
			Cap:        5 * time.Second,
		},
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected single attempt, got %d", hits.Load())
	}
	if elapsed > time.Second {
		t.Fatalf("fail-fast took too long: %v", elapsed)
	}
}

func TestNew_permissionDeniedFailFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()

	sid := writeSecretID(t, "secret")
	_, err := New(context.Background(), Options{
		Address:      srv.URL,
		Env:          "dev",
		Service:      "chat",
		RoleID:       "role",
		SecretIDFile: sid,
		Timeout:      10 * time.Second,
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestNew_sealedRetriesThenTimeout(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"errors":["Vault is sealed"]}`))
	}))
	defer srv.Close()

	sid := writeSecretID(t, "secret")
	_, err := New(context.Background(), Options{
		Address:      srv.URL,
		Env:          "dev",
		Service:      "chat",
		RoleID:       "role",
		SecretIDFile: sid,
		Timeout:      1500 * time.Millisecond,
		Retry: RetryPolicy{
			Base:       100 * time.Millisecond,
			Multiplier: 2,
			Cap:        200 * time.Millisecond,
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if !errors.Is(err, ErrSealed) {
		t.Fatalf("want ErrSealed cause, got %v", err)
	}
	if !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("error should name sealed: %v", err)
	}
	if hits.Load() < 2 {
		t.Fatalf("expected retries, hits=%d", hits.Load())
	}
}

func TestNew_closeDoesNotRevoke(t *testing.T) {
	var revoked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "tok",
					"accessor":       "acc",
					"lease_duration": 60,
					"renewable":      false,
					"policies":       []string{"default"},
				},
			})
		case "/v1/auth/token/revoke-self":
			revoked.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sid := writeSecretID(t, "secret")
	loader, err := New(context.Background(), Options{
		Address:      srv.URL,
		Env:          "dev",
		Service:      "chat",
		RoleID:       "role",
		SecretIDFile: sid,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Close(); err != nil {
		t.Fatal(err)
	}
	if revoked.Load() {
		t.Fatal("Close must not revoke")
	}
}
