package confkit

import (
	"math/rand"
	"testing"
	"time"
)

func TestNextBackoff_growsAndCaps(t *testing.T) {
	p := RetryPolicy{Base: 500 * time.Millisecond, Multiplier: 2, Cap: 5 * time.Second}
	// Deterministic: nil rnd returns the uncapped-then-capped interval with no jitter.
	got0 := nextBackoff(0, p, nil)
	got1 := nextBackoff(1, p, nil)
	got2 := nextBackoff(2, p, nil)
	got3 := nextBackoff(3, p, nil)
	got10 := nextBackoff(10, p, nil)

	if got0 != 500*time.Millisecond {
		t.Fatalf("attempt0=%v", got0)
	}
	if got1 != time.Second {
		t.Fatalf("attempt1=%v", got1)
	}
	if got2 != 2*time.Second {
		t.Fatalf("attempt2=%v", got2)
	}
	if got3 != 4*time.Second {
		t.Fatalf("attempt3=%v", got3)
	}
	if got10 != 5*time.Second {
		t.Fatalf("attempt10=%v want cap", got10)
	}
}

func TestNextBackoff_jitterBounded(t *testing.T) {
	p := RetryPolicy{Base: time.Second, Multiplier: 2, Cap: 5 * time.Second}
	rnd := rand.New(rand.NewSource(42))
	for attempt := 0; attempt < 8; attempt++ {
		got := nextBackoff(attempt, p, rnd)
		cap := p.Base
		for i := 0; i < attempt; i++ {
			cap *= 2
			if cap > p.Cap {
				cap = p.Cap
				break
			}
		}
		if got < 0 || got > cap {
			t.Fatalf("attempt %d: got %v outside [0, %v]", attempt, got, cap)
		}
	}
}
