package confkit

import (
	"fmt"
	"strings"
)

// expandPath turns a logical vault tag path into the secret path for
// KVv2.Get and the full API path used in error messages.
//
//	shared/alpha  → secret "{env}/shared/alpha",  api "{mount}/data/{env}/shared/alpha"
//	self/beta     → secret "{env}/{service}/beta", api "{mount}/data/{env}/{service}/beta"
func expandPath(logical, env, service, mount string) (secretPath, apiPath string, err error) {
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
	apiPath = mount + "/data/" + secretPath
	return secretPath, apiPath, nil
}

// envVarFromTag derives the local-mode environment variable name.
// Drops the shared/ or self/ prefix, joins remaining path segments and
// the key with underscores, and uppercases the result.
//
//	shared/alpha:user_name → ALPHA_USER_NAME
//	self/beta:token        → BETA_TOKEN
func envVarFromTag(logicalPath, key string) string {
	rest := logicalPath
	switch {
	case strings.HasPrefix(rest, "shared/"):
		rest = strings.TrimPrefix(rest, "shared/")
	case strings.HasPrefix(rest, "self/"):
		rest = strings.TrimPrefix(rest, "self/")
	}
	parts := strings.Split(rest, "/")
	parts = append(parts, key)
	for i, p := range parts {
		parts[i] = strings.ToUpper(p)
	}
	return strings.Join(parts, "_")
}
