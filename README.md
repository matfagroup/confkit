# confkit

Go library for authenticating messaging-platform microservices to HashiCorp Vault via AppRole at startup.

**This library fetches secrets once at startup and does not watch for changes.** There is no hot-reload, no `LifetimeWatcher`, and no long-lived Vault connection after bootstrap. Phase 1 covers authentication only; reading KV secrets comes next.

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

The AppRole `secret_id` is read from the file at `VAULT_SECRET_ID_FILE`, never from an environment variable.

When `APP_ENV=local`, `New` returns a loader with `IsLocal() == true` and never dials Vault. `TokenInfo` returns `(nil, nil)` in local mode.

## Token use limits

Our AppRole roles are configured with `token_num_uses=20`. Each authenticated Vault call consumes one use of the issued token. `cmd/probe` performs login, lookup-self, and revoke-self (three operations; fine for the ceiling).

In the next phase each KV path read also consumes one use. A service that reads many paths can hit the ceiling and get HTTP 403 — which looks identical to a policy mistake. Plan path counts against `token_num_uses`, or raise the limit / use an unlimited token for high-path services. No code change in this phase — just do not lose hours debugging a 403 that is really use exhaustion.

## Public API (phase 1)

```go
opts, err := confkit.OptionsFromEnv()
loader, err := confkit.New(ctx, opts)
defer loader.Close() // releases resources; does NOT revoke

info, err := loader.TokenInfo(ctx) // (nil, nil) when local
_ = loader.RevokeSelf(ctx)         // explicit; Close does not revoke
```

The raw Vault token is never exported.

## Acceptance scenarios (`cmd/probe`)

Build the probe:

```sh
go build -o bin/probe ./cmd/probe
```

### 1. Vault healthy and unsealed

```sh
export APP_ENV=dev
export SERVICE_NAME=probe
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_ROLE_ID=...
export VAULT_SECRET_ID_FILE=/path/to/secret_id

./bin/probe
```

Expect: login succeeds, prints accessor / TTL / policies, revokes cleanly, exit 0.

### 2. Vault sealed

Seal Vault (or point at a sealed instance) and run the same command with a short timeout:

```sh
export CONFKIT_TIMEOUT=5s
./bin/probe
```

Expect: INFO retry lines in the log, then a timeout error whose cause names sealed (`errors.Is(err, confkit.ErrSealed)` and `errors.Is(err, confkit.ErrTimeout)` both hold). Non-zero exit.

### 3. Wrong `VAULT_ROLE_ID`

```sh
export VAULT_ROLE_ID=definitely-wrong
./bin/probe
```

Expect: failure in under a second, no retries, message clearly indicates invalid credentials. Non-zero exit.

### 4. Local mode

```sh
export APP_ENV=local
export SERVICE_NAME=probe
# VAULT_* not required

./bin/probe
```

Expect: returns immediately, `local: true`, no network activity, exit 0.

## Develop

```sh
go test ./...
go vet ./...
go build ./...
```

Only dependency: `github.com/hashicorp/vault/api`. Logging uses `log/slog`.
