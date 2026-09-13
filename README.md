# confkit

Go library for loading HashiCorp Vault secrets into Go services at startup via AppRole.

**This library fetches secrets once at startup and does not watch for changes.** There is no hot-reload, no `LifetimeWatcher`, and no long-lived Vault connection after bootstrap.

Module: `github.com/matfagroup/confkit`

## Environment variables

| Variable | Required | Default |
|---|---|---|
| `APP_ENV` | yes | — (`dev` \| `staging` \| `prod` \| `local`) |
| `SERVICE_NAME` | yes | — |
| `VAULT_ADDR` | yes, unless `APP_ENV=local` | — |
| `VAULT_ROLE_ID` | yes, unless `APP_ENV=local` | — |
| `VAULT_SECRET_ID_FILE` | no | `/run/secrets/vault_secret_id` |
| `CONFKIT_TIMEOUT` | no | `60s` |
| `CONFKIT_KV_MOUNT` | no | `kv` |
| `CONFKIT_PREFIX` | no | empty |

The AppRole `secret_id` is read from the file at `VAULT_SECRET_ID_FILE`, never from an environment variable.

When `APP_ENV=local`, `New` returns a loader with `IsLocal() == true` and never dials Vault. `TokenInfo` returns `(nil, nil)` in local mode. `Into` fills fields from environment variables instead (see below).

## Public API

```go
opts, err := confkit.OptionsFromEnv()
loader, err := confkit.New(ctx, opts)
defer loader.Close() // releases resources; does NOT revoke

info, err := loader.TokenInfo(ctx) // (nil, nil) when local

var secrets MySecrets
err = loader.Into(ctx, &secrets)
fmt.Println(loader.SecretReads()) // reads performed by the most recent Into

_ = loader.RevokeSelf(ctx) // explicit; Close does not revoke
```

The raw Vault token is never exported.

## Reading secrets with `Into`

Tag string fields with `vault:"logical/path:key"`:

```go
type Secrets struct {
    Postgres struct {
        PrimaryUsername string `vault:"shared/postgres:primary_username"`
        PrimaryPassword string `vault:"shared/postgres:primary_password"`
    }
    JWT struct {
        AccessSecret string `vault:"self/jwt:access_secret"`
    }
}
```

**Only `string` fields are supported.** A non-string field with a `vault` tag is a fatal error. There is **no** `optional` modifier — every tagged field must be present. Untagged and unexported fields are skipped. Nested structs are walked recursively.

### Path expansion

| Logical path | Expands to (API), prefix empty | Expands to (API), with prefix |
|---|---|---|
| `shared/postgres` | `{mount}/data/{env}/shared/postgres` | `{mount}/data/{prefix}/{env}/shared/postgres` |
| `self/jwt` | `{mount}/data/{env}/{service}/jwt` | `{mount}/data/{prefix}/{env}/{service}/jwt` |

Default mount is `kv` (`CONFKIT_KV_MOUNT`). The `data` segment is required for KV v2; policies written against CLI paths without `data` will 403.

`CONFKIT_PREFIX` is an optional single path segment under the mount that groups one platform's secrets when several platforms share the same KV engine. Empty (the default) preserves paths rooted at `{env}/...`. Our messenger platform uses `CONFKIT_PREFIX=messenger`, so a tag `shared/postgres` becomes `kv/data/messenger/dev/shared/postgres` — not `kv/data/dev/shared/postgres`.

Any logical-path prefix other than `shared/` or `self/` is a fatal configuration error.

### One read per path

`Into` groups fields by expanded path and issues **exactly one Vault read per distinct path**. Four fields on `shared/postgres` produce one request, not four. This matters because AppRole tokens use `token_num_uses=20`. `SecretReads()` reports the count for the most recent `Into` call (reset at the start of each call).

### Local-mode environment names

When `APP_ENV=local`, each tag maps to an environment variable by dropping the `shared/` or `self/` prefix, joining the remaining path segments and key with `_`, and uppercasing:

| Tag | Environment variable |
|---|---|
| `shared/postgres:primary_username` | `POSTGRES_PRIMARY_USERNAME` |
| `self/jwt:access_secret` | `JWT_ACCESS_SECRET` |

If two tags would map to the same variable (e.g. `shared/alpha:user` and `self/alpha:user` → `ALPHA_USER`), `Into` fails with `ErrInvalidTag` in **all** modes — not only local — so collisions surface in shared environments.

Local mode is the **only** environment fallback. Non-local `Into` never reads env vars.

## Token use limits

Our AppRole roles are configured with `token_num_uses=20`. Each authenticated Vault call consumes one use of the issued token. `cmd/probe` performs login, lookup-self, KV reads, and revoke-self.

Each distinct KV path read consumes one use. Plan path counts against the ceiling, or raise `token_num_uses` for high-path services — a 403 from use exhaustion looks identical to a policy mistake.

## Acceptance scenarios (`cmd/probe`)

```sh
go build -o bin/probe ./cmd/probe
```

### Auth (phase 1)

1. Vault healthy → login OK, accessor/TTL/policies, revoke clean  
2. Vault sealed → retries then timeout naming sealed  
3. Wrong `VAULT_ROLE_ID` → fail-fast, invalid credentials  
4. `APP_ENV=local` → immediate, no network  

### Secrets (phase 2)

After auth output, probe fills a synthetic struct via `Into`, prints masked values with lengths, and the read count.

1. Valid struct → fields filled, `reads` equals distinct paths  
2. Missing key → error naming field, path, and key  
3. Path denied by policy → error naming the expanded API path  
4. Non-string tagged field → fatal error naming field and type  
5. `APP_ENV=local` with the env vars above → filled, `reads: 0`  

For local probe:

```sh
export APP_ENV=local
export SERVICE_NAME=probe
export ALPHA_USER=...
export ALPHA_PASS=...
export BETA_TOKEN=...
./bin/probe
```

## Develop

```sh
go test ./...
go vet ./...
go build ./...
```

Only dependency: `github.com/hashicorp/vault/api`. Logging uses `log/slog`.
