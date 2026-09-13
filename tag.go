package confkit

import (
	"fmt"
	"reflect"
	"strings"
)

// fieldBinding ties one tagged struct field to its Vault (or local env) source.
type fieldBinding struct {
	fieldPath  string // e.g. "Config.Alpha.User"
	value      reflect.Value
	logical    string // e.g. "shared/alpha"
	key        string // e.g. "user"
	secretPath string // path passed to KVv2.Get, e.g. "dev/shared/alpha"
	apiPath    string // full API path for errors, e.g. "kv/data/dev/shared/alpha"
	envVar     string // local-mode variable name
	tag        string // original vault tag value
}

// parseVaultTag parses vault:"logical/path:key".
func parseVaultTag(tag string) (logicalPath, key string, err error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", "", fmt.Errorf("%w: empty vault tag", ErrInvalidTag)
	}
	logicalPath, key, ok := strings.Cut(tag, ":")
	if !ok || logicalPath == "" || key == "" {
		return "", "", fmt.Errorf("%w: malformed vault tag %q (want path:key)", ErrInvalidTag, tag)
	}
	if strings.Contains(key, ":") {
		return "", "", fmt.Errorf("%w: malformed vault tag %q (want path:key)", ErrInvalidTag, tag)
	}
	return logicalPath, key, nil
}

// collectBindings walks dst (pointer to struct) and returns every vault-tagged field.
func collectBindings(dst any, env, service, mount, pathPrefix string) ([]fieldBinding, error) {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil, fmt.Errorf("%w: dst must be a non-nil pointer to a struct", ErrInvalidTag)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%w: dst must be a non-nil pointer to a struct", ErrInvalidTag)
	}

	var out []fieldBinding
	if err := walkStruct(v, v.Type().Name(), env, service, mount, pathPrefix, &out); err != nil {
		return nil, err
	}

	if err := detectEnvCollisions(out); err != nil {
		return nil, err
	}
	return out, nil
}

func walkStruct(v reflect.Value, fieldPrefix, env, service, mount, pathPrefix string, out *[]fieldBinding) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if sf.PkgPath != "" {
			continue // unexported
		}
		fv := v.Field(i)
		fieldPath := fieldPrefix + "." + sf.Name
		if fieldPrefix == "" {
			fieldPath = sf.Name
		}

		tag, hasTag := sf.Tag.Lookup("vault")

		switch fv.Kind() {
		case reflect.Struct:
			if hasTag {
				return fmt.Errorf("%w: field %s has type %s, only string is supported", ErrInvalidTag, fieldPath, fv.Type())
			}
			if err := walkStruct(fv, fieldPath, env, service, mount, pathPrefix, out); err != nil {
				return err
			}
			continue
		case reflect.Pointer:
			if hasTag {
				return fmt.Errorf("%w: field %s has type %s, only string is supported", ErrInvalidTag, fieldPath, fv.Type())
			}
			if fv.IsNil() {
				continue
			}
			if fv.Elem().Kind() == reflect.Struct {
				if err := walkStruct(fv.Elem(), fieldPath, env, service, mount, pathPrefix, out); err != nil {
					return err
				}
			}
			continue
		}

		if !hasTag {
			continue
		}
		if fv.Kind() != reflect.String {
			return fmt.Errorf("%w: field %s has type %s, only string is supported", ErrInvalidTag, fieldPath, fv.Type())
		}
		if !fv.CanSet() {
			return fmt.Errorf("%w: field %s is not settable", ErrInvalidTag, fieldPath)
		}

		logical, key, err := parseVaultTag(tag)
		if err != nil {
			return fmt.Errorf("%w: field %s: %v", ErrInvalidTag, fieldPath, err)
		}
		secretPath, apiPath, err := expandPath(logical, env, service, mount, pathPrefix)
		if err != nil {
			return fmt.Errorf("%w: field %s: %v", ErrInvalidTag, fieldPath, err)
		}

		*out = append(*out, fieldBinding{
			fieldPath:  fieldPath,
			value:      fv,
			logical:    logical,
			key:        key,
			secretPath: secretPath,
			apiPath:    apiPath,
			envVar:     envVarFromTag(logical, key),
			tag:        tag,
		})
	}
	return nil
}

// detectEnvCollisions fails when two tags map to the same local-mode env var.
// Checked in all modes so collisions surface in non-local environments too.
func detectEnvCollisions(bindings []fieldBinding) error {
	seen := make(map[string]fieldBinding, len(bindings))
	for _, b := range bindings {
		if prev, ok := seen[b.envVar]; ok {
			return fmt.Errorf("%w: env var %s collides for fields %s and %s (tags %q and %q)",
				ErrInvalidTag, b.envVar, prev.fieldPath, b.fieldPath, prev.tag, b.tag)
		}
		seen[b.envVar] = b
	}
	return nil
}
