package confkit

import (
	"errors"
	"strings"
	"testing"
)

func TestParseVaultTag(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		wantPath string
		wantKey  string
		wantErr  bool
	}{
		{name: "valid shared", tag: "shared/alpha:user", wantPath: "shared/alpha", wantKey: "user"},
		{name: "valid self", tag: "self/beta:token", wantPath: "self/beta", wantKey: "token"},
		{name: "empty", tag: "", wantErr: true},
		{name: "no colon", tag: "shared/alpha", wantErr: true},
		{name: "empty key", tag: "shared/alpha:", wantErr: true},
		{name: "empty path", tag: ":key", wantErr: true},
		{name: "extra colon", tag: "shared/alpha:a:b", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, key, err := parseVaultTag(tt.tag)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !errors.Is(err, ErrInvalidTag) {
					t.Fatalf("want ErrInvalidTag, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if path != tt.wantPath || key != tt.wantKey {
				t.Fatalf("got %q %q", path, key)
			}
		})
	}
}

func TestCollectBindings_unknownPrefix(t *testing.T) {
	var dst struct {
		X string `vault:"other/thing:key"`
	}
	_, err := collectBindings(&dst, "dev", "svc", "kv")
	if !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown path prefix") {
		t.Fatalf("msg=%v", err)
	}
}

func TestCollectBindings_envCollision(t *testing.T) {
	var dst struct {
		A string `vault:"shared/alpha:user"`
		B string `vault:"self/alpha:user"`
	}
	_, err := collectBindings(&dst, "dev", "svc", "kv")
	if !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "collides") || !strings.Contains(err.Error(), "ALPHA_USER") {
		t.Fatalf("msg=%v", err)
	}
}

func TestCollectBindings_nonStringTagged(t *testing.T) {
	var dst struct {
		N int `vault:"shared/alpha:n"`
	}
	_, err := collectBindings(&dst, "dev", "svc", "kv")
	if !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "int") {
		t.Fatalf("msg=%v", err)
	}
}
