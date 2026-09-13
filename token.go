package confkit

import "time"

// TokenInfo describes the authenticated Vault token without exposing the
// token string itself. Callers have no legitimate need for the raw token;
// an accessor leaking into a log is far less damaging.
type TokenInfo struct {
	Accessor  string
	TTL       time.Duration
	Renewable bool
	Policies  []string
}
