package confkit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecretID_trimsNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sid")
	if err := os.WriteFile(path, []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readSecretID(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("got %q", got)
	}
}

func TestReadSecretID_rejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sid")
	if err := os.WriteFile(path, []byte("\n\t  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readSecretID(path, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestReadSecretID_missing(t *testing.T) {
	_, err := readSecretID(filepath.Join(t.TempDir(), "nope"), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("got %v", err)
	}
}
