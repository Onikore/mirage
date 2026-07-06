package protocol

// replay.go — анти-replay кэш для msg1: не даёт дважды успешно
// аутентифицировать один и тот же эфемерный pubkey клиента в пределах окна.
//
// Проверяется ТОЛЬКО после успешной psk-аутентификации (см. handshake.go) —
// мусор и неверный psk кэш не засоряют.
//
// ponytail: чистка протухших записей — полный проход по карте при каждой
// проверке (O(n)); апгрейд на bloom-filter/тикер, если объём трафика когда-
// нибудь это оправдает.

import (
	"sync"
	"time"
)

const ReplayWindow = 2 * time.Minute

type ReplayCache struct {
	window time.Duration
	mu     sync.Mutex
	seen   map[[32]byte]time.Time
}

func NewReplayCache(window time.Duration) *ReplayCache {
	return &ReplayCache{window: window, seen: make(map[[32]byte]time.Time)}
}

// checkAndRemember возвращает true, если ecPub уже встречался в пределах
// окна (replay). Иначе запоминает его с текущим временем и возвращает false.
func (c *ReplayCache) checkAndRemember(ecPub []byte) bool {
	var key [32]byte
	copy(key[:], ecPub)

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, t := range c.seen {
		if now.Sub(t) > c.window {
			delete(c.seen, k)
		}
	}

	if _, replay := c.seen[key]; replay {
		return true
	}
	c.seen[key] = now
	return false
}
