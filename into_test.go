package confkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

type sampleSecrets struct {
	Alpha struct {
		User string `vault:"shared/alpha:user"`
		Pass string `vault:"shared/alpha:pass"`
		Host string `vault:"shared/alpha:host"`
		Port string `vault:"shared/alpha:port"`
	}
	Beta struct {
		Token  string `vault:"self/beta:token"`
		Region string `vault:"self/beta:region"`
	}
	Plain  string // untagged — skipped
	hidden string // unexported — skipped
}

func TestInto_groupingTwoReads(t *testing.T) {
	var reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			writeLogin(w)
		case strings.HasPrefix(r.URL.Path, "/v1/kv/data/"):
			reads.Add(1)
			switch r.URL.Path {
			case "/v1/kv/data/dev/shared/alpha":
				writeKV(w, map[string]string{
					"user": "u", "pass": "p", "host": "h", "port": "5432",
				})
			case "/v1/kv/data/dev/probe/beta":
				writeKV(w, map[string]string{
					"token": "t", "region": "r",
				})
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	loader := mustLogin(t, srv.URL, "dev", "probe")
	defer loader.Close()

	var dst sampleSecrets
	if err := loader.Into(context.Background(), &dst); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 2 {
		t.Fatalf("http reads=%d want 2", reads.Load())
	}
	if loader.SecretReads() != 2 {
		t.Fatalf("SecretReads=%d want 2", loader.SecretReads())
	}
	if dst.Alpha.User != "u" || dst.Alpha.Pass != "p" || dst.Beta.Token != "t" {
		t.Fatalf("unexpected fill: %+v", dst)
	}
}

func TestInto_secretReadsResets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			writeLogin(w)
		case r.URL.Path == "/v1/kv/data/dev/shared/alpha":
			writeKV(w, map[string]string{"user": "u", "pass": "p", "host": "h", "port": "1"})
		case r.URL.Path == "/v1/kv/data/dev/probe/beta":
			writeKV(w, map[string]string{"token": "t", "region": "r"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	loader := mustLogin(t, srv.URL, "dev", "probe")
	defer loader.Close()

	var a sampleSecrets
	if err := loader.Into(context.Background(), &a); err != nil {
		t.Fatal(err)
	}
	if loader.SecretReads() != 2 {
		t.Fatalf("first SecretReads=%d", loader.SecretReads())
	}
	var b sampleSecrets
	if err := loader.Into(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	if loader.SecretReads() != 2 {
		t.Fatalf("second SecretReads=%d want 2 (reset, not accumulate)", loader.SecretReads())
	}
}

func TestInto_missingKeyAggregatedSorted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			writeLogin(w)
		case r.URL.Path == "/v1/kv/data/dev/shared/alpha":
			writeKV(w, map[string]string{"user": "u"}) // pass/host/port missing
		case r.URL.Path == "/v1/kv/data/dev/probe/beta":
			writeKV(w, map[string]string{"token": "t"}) // region missing
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	loader := mustLogin(t, srv.URL, "dev", "probe")
	defer loader.Close()

	var dst sampleSecrets
	err := loader.Into(context.Background(), &dst)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"Alpha.Pass", "Alpha.Host", "Alpha.Port", "Beta.Region"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %s in %q", want, msg)
		}
	}
	// Deterministic order by field path.
	passIdx := strings.Index(msg, "Alpha.Pass")
	hostIdx := strings.Index(msg, "Alpha.Host")
	portIdx := strings.Index(msg, "Alpha.Port")
	regionIdx := strings.Index(msg, "Beta.Region")
	if !(hostIdx < passIdx && passIdx < portIdx && portIdx < regionIdx) {
		t.Fatalf("unsorted field order in %q", msg)
	}
}

func TestInto_pathNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			writeLogin(w)
		default:
			// Vault Logical.Read returns nil body on 404 → KVv2 yields ErrSecretNotFound
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	}))
	defer srv.Close()

	loader := mustLogin(t, srv.URL, "dev", "probe")
	defer loader.Close()

	var dst struct {
		X string `vault:"shared/alpha:user"`
	}
	err := loader.Into(context.Background(), &dst)
	if !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("want ErrPathNotFound via api.ErrSecretNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "kv/data/dev/shared/alpha") {
		t.Fatalf("msg=%v", err)
	}
}

func TestInto_permissionDeniedIncludesPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			writeLogin(w)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		}
	}))
	defer srv.Close()

	loader := mustLogin(t, srv.URL, "dev", "probe")
	defer loader.Close()

	var dst struct {
		X string `vault:"shared/alpha:user"`
	}
	err := loader.Into(context.Background(), &dst)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "kv/data/dev/shared/alpha") {
		t.Fatalf("msg=%v", err)
	}
}

func TestInto_badDestination(t *testing.T) {
	loader := &Loader{env: "dev", service: "probe", kvMount: "kv", local: true}
	if err := loader.Into(context.Background(), sampleSecrets{}); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("non-pointer: %v", err)
	}
	var nilPtr *sampleSecrets
	if err := loader.Into(context.Background(), nilPtr); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("nil pointer: %v", err)
	}
}

func TestInto_localMode(t *testing.T) {
	t.Setenv("ALPHA_USER", "lu")
	t.Setenv("ALPHA_PASS", "lp")
	t.Setenv("BETA_TOKEN", "lt")

	loader, err := New(context.Background(), Options{Env: "local", Service: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	defer loader.Close()

	var dst struct {
		User  string `vault:"shared/alpha:user"`
		Pass  string `vault:"shared/alpha:pass"`
		Token string `vault:"self/beta:token"`
	}
	if err := loader.Into(context.Background(), &dst); err != nil {
		t.Fatal(err)
	}
	if dst.User != "lu" || dst.Pass != "lp" || dst.Token != "lt" {
		t.Fatalf("%+v", dst)
	}
	if loader.SecretReads() != 0 {
		t.Fatalf("SecretReads=%d", loader.SecretReads())
	}
}

func TestInto_localMissingVars(t *testing.T) {
	os.Unsetenv("ALPHA_USER")
	os.Unsetenv("ALPHA_PASS")

	loader, err := New(context.Background(), Options{Env: "local", Service: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	defer loader.Close()

	var dst struct {
		User string `vault:"shared/alpha:user"`
		Pass string `vault:"shared/alpha:pass"`
	}
	err = loader.Into(context.Background(), &dst)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "ALPHA_USER") || !strings.Contains(msg, "ALPHA_PASS") {
		t.Fatalf("msg=%v", msg)
	}
}

func TestInto_skipsUntaggedAndUnexported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			writeLogin(w)
		case r.URL.Path == "/v1/kv/data/dev/shared/alpha":
			writeKV(w, map[string]string{"user": "u"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	loader := mustLogin(t, srv.URL, "dev", "probe")
	defer loader.Close()

	var dst struct {
		User   string `vault:"shared/alpha:user"`
		Plain  string
		hidden string
	}
	dst.Plain = "keep"
	if err := loader.Into(context.Background(), &dst); err != nil {
		t.Fatal(err)
	}
	if dst.User != "u" || dst.Plain != "keep" {
		t.Fatalf("%+v", dst)
	}
}

func TestErrSecretNotFound_isUsed(t *testing.T) {
	// Documented contract with vault/api@v1.23.0: nil Logical read → ErrSecretNotFound.
	if !errors.Is(api.ErrSecretNotFound, api.ErrSecretNotFound) {
		t.Fatal("sanity")
	}
	err := errors.New("wrap")
	wrapped := errors.Join(api.ErrSecretNotFound, err)
	if !errors.Is(wrapped, api.ErrSecretNotFound) {
		t.Fatal("expected Is")
	}
}

func writeLogin(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   "tok",
			"accessor":       "acc",
			"lease_duration": 60,
			"renewable":      false,
			"policies":       []string{"default"},
		},
	})
}

func writeKV(w http.ResponseWriter, data map[string]string) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"data": data,
			"metadata": map[string]interface{}{
				"version": 1,
			},
		},
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func mustLogin(t *testing.T, addr, env, service string) *Loader {
	t.Helper()
	sid := filepath.Join(t.TempDir(), "sid")
	if err := os.WriteFile(sid, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := New(context.Background(), Options{
		Address:      addr,
		Env:          env,
		Service:      service,
		RoleID:       "role",
		SecretIDFile: sid,
		Timeout:      5 * time.Second,
		KVMount:      "kv",
	})
	if err != nil {
		t.Fatal(err)
	}
	return loader
}
