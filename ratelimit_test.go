package main

import (
	"testing"
	"time"
)

func TestIPLimiterAllowsBurstThenBlocks(t *testing.T) {
	l := newIPLimiter()

	for i := 0; i < rateLimitBurst; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("attempt %d within burst was blocked", i)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("attempt beyond burst was allowed")
	}
}

func TestIPLimiterRefillsOverTime(t *testing.T) {
	l := newIPLimiter()
	for i := 0; i < rateLimitBurst; i++ {
		l.allow("1.2.3.4")
	}
	if l.allow("1.2.3.4") {
		t.Fatal("expected to be blocked immediately after exhausting burst")
	}

	time.Sleep(2*time.Second + 100*time.Millisecond) // >= 1 token at 0.5/sec
	if !l.allow("1.2.3.4") {
		t.Fatal("expected a token to be available after refill interval")
	}
}

func TestIPLimiterDistinctIPsIndependent(t *testing.T) {
	l := newIPLimiter()
	for i := 0; i < rateLimitBurst; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("attempt %d for first IP within burst was blocked", i)
		}
	}
	if !l.allow("5.6.7.8") {
		t.Fatal("first attempt for a distinct IP was blocked")
	}
}
