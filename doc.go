// Package confkit authenticates Go services to HashiCorp Vault via AppRole
// at startup. Secrets are fetched once; this library does not watch for
// changes or renew tokens.
//
// Phase 1 covers authentication only. Reading KV secrets is a later phase.
package confkit
