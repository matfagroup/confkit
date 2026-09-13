package confkit

import (
	"math"
	"math/rand"
	"time"
)

// nextBackoff returns the sleep duration for the given 0-based attempt.
// Interval = min(Base * Multiplier^attempt, Cap) with full jitter in [0, interval].
func nextBackoff(attempt int, p RetryPolicy, rnd *rand.Rand) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	mult := math.Pow(p.Multiplier, float64(attempt))
	interval := time.Duration(float64(p.Base) * mult)
	if interval > p.Cap {
		interval = p.Cap
	}
	if interval <= 0 {
		return 0
	}
	if rnd == nil {
		return interval
	}
	// Full jitter: [0, interval].
	n := rnd.Int63n(int64(interval) + 1)
	return time.Duration(n)
}
