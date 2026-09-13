package confkit

import (
	"errors"
	"testing"
)

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name       string
		logical    string
		env        string
		service    string
		mount      string
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
			secret, apiPath, err := expandPath(tt.logical, tt.env, tt.service, tt.mount)
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
