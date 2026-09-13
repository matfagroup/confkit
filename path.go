package confkit

import (
	"fmt"
	"strings"
)

// expandPath turns a logical vault tag path into the secret path for
// KVv2.Get and the full API path used in error messages.
//
// With pathPrefix empty:
//
//	shared/alpha  → secret "{env}/shared/alpha",  api "{mount}/data/{env}/shared/alpha"
//	self/beta     → secret "{env}/{service}/beta", api "{mount}/data/{env}/{service}/beta"
//
// With pathPrefix set (e.g. "messenger"):
//
//	shared/alpha  → secret "{prefix}/{env}/shared/alpha"
//	self/beta     → secret "{prefix}/{env}/{service}/beta"
func expandPath(logical, env, service, mount, pathPrefix string) (secretPath, apiPath string, err error) {
	logical = strings.TrimSpace(logical)
	switch {
	case strings.HasPrefix(logical, "shared/"):
		rest := strings.TrimPrefix(logical, "shared/")
		if rest == "" || strings.HasPrefix(rest, "/") {
			return "", "", fmt.Errorf("%w: empty path after shared/", ErrInvalidTag)
		}
		secretPath = env + "/shared/" + rest
	case strings.HasPrefix(logical, "self/"):
		rest := strings.TrimPrefix(logical, "self/")
		if rest == "" || strings.HasPrefix(rest, "/") {
			return "", "", fmt.Errorf("%w: empty path after self/", ErrInvalidTag)
		}
		secretPath = env + "/" + service + "/" + rest
	default:
		return "", "", fmt.Errorf("%w: unknown path prefix in %q (want shared/ or self/)", ErrInvalidTag, logical)
	}
	if pathPrefix != "" {
		secretPath = pathPrefix + "/" + secretPath
	}
	apiPath = mount + "/data/" + secretPath
	return secretPath, apiPath, nil
}

// envVarFromTag derives the local-mode environment variable name from the
// Vault key alone, uppercased. Path segments are omitted so a key that
// already carries its domain prefix maps to the same name developers use
// in .env files.
//
//	shared/redis:REDIS_PASSWORD          → REDIS_PASSWORD
//	self/jwt:JWT_WEB_ACCESS_SECRET       → JWT_WEB_ACCESS_SECRET
//	self/auth:OTP_FIXED_CODE             → OTP_FIXED_CODE
func envVarFromTag(key string) string {
	return strings.ToUpper(key)
}

// validatePrefix trims surrounding whitespace and checks that prefix is a
// single path segment (or empty). The trimmed value is returned for storage.
func validatePrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", nil
	}
	if prefix == "." || prefix == ".." {
		return "", fmt.Errorf("%w: CONFKIT_PREFIX %q is not allowed", ErrMissingConfig, prefix)
	}
	if strings.Contains(prefix, "/") {
		return "", fmt.Errorf("%w: CONFKIT_PREFIX %q must be a single path segment (no slashes)", ErrMissingConfig, prefix)
	}
	if strings.ContainsAny(prefix, " \t\n\r") {
		return "", fmt.Errorf("%w: CONFKIT_PREFIX %q must not contain whitespace", ErrMissingConfig, prefix)
	}
	return prefix, nil
}
