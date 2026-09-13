package confkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Into reads Vault KV v2 secrets (or local environment variables) into dst.
// dst must be a non-nil pointer to a struct whose string fields carry
// vault:"path:key" tags. Only string fields are supported; every tagged
// field is required. Untagged and unexported fields are skipped.
//
// Exactly one Vault read is issued per distinct expanded path. SecretReads
// reports the number of reads performed by this call.
func (l *Loader) Into(ctx context.Context, dst any) error {
	l.secretReads = 0

	if l.closed {
		return fmt.Errorf("loader is closed")
	}

	mount := l.kvMount
	if mount == "" {
		mount = defaultKVMount
	}

	bindings, err := collectBindings(dst, l.env, l.service, mount, l.prefix)
	if err != nil {
		return err
	}
	if len(bindings) == 0 {
		return nil
	}

	if l.local {
		return l.intoLocal(bindings)
	}
	return l.intoVault(ctx, bindings, mount)
}

// SecretReads returns the number of Vault KV reads performed by the most
// recent Into call. It is reset to zero at the start of each Into. Local
// mode always leaves this at zero.
func (l *Loader) SecretReads() int {
	return l.secretReads
}

func (l *Loader) intoLocal(bindings []fieldBinding) error {
	var fieldErrs []error
	for _, b := range bindings {
		val, ok := os.LookupEnv(b.envVar)
		if !ok || val == "" {
			fieldErrs = append(fieldErrs, fmt.Errorf(
				"%w: field %s: environment variable %s not set (from tag %q)",
				ErrKeyNotFound, b.fieldPath, b.envVar, b.tag,
			))
			continue
		}
		b.value.SetString(val)
	}
	return joinFieldErrors(fieldErrs)
}

func (l *Loader) intoVault(ctx context.Context, bindings []fieldBinding, mount string) error {
	if l.client == nil {
		return fmt.Errorf("loader has no vault client")
	}

	// Group fields by secret path — one read per distinct path.
	groups := make(map[string][]fieldBinding)
	order := make([]string, 0)
	for _, b := range bindings {
		if _, seen := groups[b.secretPath]; !seen {
			order = append(order, b.secretPath)
		}
		groups[b.secretPath] = append(groups[b.secretPath], b)
	}

	kv := l.client.KVv2(mount)
	dataByPath := make(map[string]map[string]interface{}, len(groups))
	var fieldErrs []error

	for _, secretPath := range order {
		group := groups[secretPath]
		apiPath := group[0].apiPath

		secret, err := kv.Get(ctx, secretPath)
		l.secretReads++
		if err != nil {
			if errors.Is(err, api.ErrSecretNotFound) {
				for _, b := range group {
					fieldErrs = append(fieldErrs, fmt.Errorf(
						"%w: field %s: path %s not found",
						ErrPathNotFound, b.fieldPath, apiPath,
					))
				}
				continue
			}
			var respErr *api.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == 403 {
				return fmt.Errorf("%w: reading %s: %w", ErrPermissionDenied, apiPath, err)
			}
			classified, _ := classify(err)
			if errors.Is(classified, ErrPermissionDenied) {
				return fmt.Errorf("%w: reading %s: %w", ErrPermissionDenied, apiPath, classified)
			}
			return fmt.Errorf("reading %s: %w", apiPath, classified)
		}
		if secret == nil || secret.Data == nil {
			for _, b := range group {
				fieldErrs = append(fieldErrs, fmt.Errorf(
					"%w: field %s: path %s not found",
					ErrPathNotFound, b.fieldPath, apiPath,
				))
			}
			continue
		}
		dataByPath[secretPath] = secret.Data
	}

	for _, b := range bindings {
		data, ok := dataByPath[b.secretPath]
		if !ok {
			continue // already recorded as path error
		}
		raw, exists := data[b.key]
		if !exists {
			fieldErrs = append(fieldErrs, fmt.Errorf(
				`%w: field %s: key %q not found at %s`,
				ErrKeyNotFound, b.fieldPath, b.key, b.apiPath,
			))
			continue
		}
		str, ok := raw.(string)
		if !ok {
			fieldErrs = append(fieldErrs, fmt.Errorf(
				"%w: field %s: key %q at %s is %T, want string",
				ErrKeyNotFound, b.fieldPath, b.key, b.apiPath, raw,
			))
			continue
		}
		b.value.SetString(str)
	}

	return joinFieldErrors(fieldErrs)
}

func joinFieldErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	sort.Slice(errs, func(i, j int) bool {
		return fieldPathFromErr(errs[i]) < fieldPathFromErr(errs[j])
	})
	return errors.Join(errs...)
}

// fieldPathFromErr extracts the "field X" segment for deterministic sorting.
func fieldPathFromErr(err error) string {
	msg := err.Error()
	const marker = "field "
	i := strings.Index(msg, marker)
	if i < 0 {
		return msg
	}
	rest := msg[i+len(marker):]
	if j := strings.IndexAny(rest, " :"); j >= 0 {
		return rest[:j]
	}
	return rest
}
