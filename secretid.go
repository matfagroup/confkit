package confkit

import (
	"fmt"
	"log/slog"
	"os"
)

// readSecretID loads the AppRole secret_id from path, trimming surrounding
// whitespace. Empty files are rejected. Group- or world-readable files
// produce a WARN but still succeed.
func readSecretID(path string, log *slog.Logger) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: secret_id file %q not found", ErrMissingConfig, path)
		}
		return nil, fmt.Errorf("%w: secret_id file %q: %v", ErrMissingConfig, path, err)
	}

	mode := info.Mode().Perm()
	if mode&0o044 != 0 && log != nil {
		log.Warn("secret_id file is group- or world-readable", "path", path, "mode", mode.String())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading secret_id file %q: %v", ErrMissingConfig, path, err)
	}

	// Trim surrounding whitespace and trailing newlines.
	start, end := 0, len(raw)
	for start < end && isSpace(raw[start]) {
		start++
	}
	for end > start && isSpace(raw[end-1]) {
		end--
	}
	trimmed := make([]byte, end-start)
	copy(trimmed, raw[start:end])
	zeroBytes(raw)

	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: secret_id file %q is empty", ErrMissingConfig, path)
	}
	return trimmed, nil
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
