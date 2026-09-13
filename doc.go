// Package confkit authenticates Go services to HashiCorp Vault via AppRole
// at startup and loads KV v2 secrets into tagged structs with Into.
// Secrets are fetched once; this library does not watch for changes or
// renew tokens.
package confkit
