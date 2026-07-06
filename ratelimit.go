package main

// ratelimit.go — per-IP ограничение частоты попыток подключения.
//
// Проверяется на входе в serveConn, до любой крипто-работы: если лимит
// превышен, соединение уходит в тот же fallback(), что и обычный зонд —
// иначе разное поведение "зонд" vs "rate limited" само стало бы
// фингерпринтом.
//
// ponytail: чистка простаивающих IP-бакетов — та же ленивая схема, что в
// replay.go (полный проход по карте при каждой проверке); апгрейд на
// тикер/LRU, если объём трафика когда-нибудь это оправдает.

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	rateLimitBurst              = 5
	rateLimitPerSec  rate.Limit = 0.5
	rateLimitIdleTTL            = 10 * time.Minute
)

type ipLimiter struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
}

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPLimiter() *ipLimiter {
	return &ipLimiter{buckets: make(map[string]*ipBucket)}
}

// allow сообщает, можно ли обслужить ещё одну попытку с этого IP прямо сейчас.
func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > rateLimitIdleTTL {
			delete(l.buckets, k)
		}
	}

	b, ok := l.buckets[ip]
	if !ok {
		b = &ipBucket{limiter: rate.NewLimiter(rateLimitPerSec, rateLimitBurst)}
		l.buckets[ip] = b
	}
	b.lastSeen = now
	return b.limiter.Allow()
}
