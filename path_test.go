package confkit

import (
	"errors"
	"strings"
	"testing"
)

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name       string
		logical    string
		env        string
		service    string
		mount      string
		pathPrefix string
		wantSecret string
		wantAPI    string
		wantErr    bool
	}{
		{
			name:       "shared default mount",
			logical:    "shared/alpha",
			env:        "dev",
			service:    "probe",
			mount:      "kv",
			wantSecret: "dev/shared/alpha",
			wantAPI:    "kv/data/dev/shared/alpha",
		},
		{
			name:       "self default mount",
			logical:    "self/beta",
			env:        "dev",
			service:    "probe",
			mount:      "kv",
			wantSecret: "dev/probe/beta",
			wantAPI:    "kv/data/dev/probe/beta",
		},
		{
			name:       "non-default mount",
			logical:    "shared/alpha",
			env:        "staging",
			service:    "svc",
			mount:      "secret",
			wantSecret: "staging/shared/alpha",
			wantAPI:    "secret/data/staging/shared/alpha",
		},
		{
			name:       "shared with prefix",
			logical:    "shared/postgres",
			env:        "dev",
			service:    "probe",
			mount:      "kv",
			pathPrefix: "messenger",
			wantSecret: "messenger/dev/shared/postgres",
			wantAPI:    "kv/data/messenger/dev/shared/postgres",
		},
		{
			name:       "self with prefix",
			logical:    "self/jwt",
			env:        "dev",
			service:    "user-auth",
			mount:      "kv",
			pathPrefix: "messenger",
			wantSecret: "messenger/dev/user-auth/jwt",
			wantAPI:    "kv/data/messenger/dev/user-auth/jwt",
		},
		{
			name:       "prefix with non-default mount",
			logical:    "shared/alpha",
			env:        "staging",
			service:    "svc",
			mount:      "secret",
			pathPrefix: "messenger",
			wantSecret: "messenger/staging/shared/alpha",
			wantAPI:    "secret/data/messenger/staging/shared/alpha",
		},
		{
			name:    "unknown prefix",
			logical: "team/alpha",
			env:     "dev",
			service: "svc",
			mount:   "kv",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, apiPath, err := expandPath(tt.logical, tt.env, tt.service, tt.mount, tt.pathPrefix)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidTag) {
					t.Fatalf("got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if secret != tt.wantSecret {
				t.Fatalf("secretPath=%q want %q", secret, tt.wantSecret)
			}
			if apiPath != tt.wantAPI {
				t.Fatalf("apiPath=%q want %q", apiPath, tt.wantAPI)
			}
		})
	}
}

func TestEnvVarFromTag(t *testing.T) {
	tests := []struct {
		logical, key, want string
	}{
		{"shared/alpha", "user_name", "ALPHA_USER_NAME"},
		{"self/beta", "token", "BETA_TOKEN"},
		{"shared/foo/bar", "baz", "FOO_BAR_BAZ"},
	}
	for _, tt := range tests {
		got := envVarFromTag(tt.logical, tt.key)
		if got != tt.want {
			t.Fatalf("envVarFromTag(%q,%q)=%q want %q", tt.logical, tt.key, got, tt.want)
		}
	}
}

func TestValidatePrefix(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty", in: "", want: ""},
		{name: "whitespace only", in: "  \t  ", want: ""},
		{name: "valid", in: "messenger", want: "messenger"},
		{name: "trims surrounding", in: "  messenger  ", want: "messenger"},
		{name: "leading slash", in: "/messenger", wantErr: true},
		{name: "trailing slash", in: "messenger/", wantErr: true},
		{name: "interior slash", in: "a/b", wantErr: true},
		{name: "interior space", in: "mess enger", wantErr: true},
		{name: "dot", in: ".", wantErr: true},
		{name: "dotdot", in: "..", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatePrefix(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrMissingConfig) {
					t.Fatalf("got %v", err)
				}
				if !strings.Contains(err.Error(), strings.TrimSpace(tt.in)) {
					t.Fatalf("error should name value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}
