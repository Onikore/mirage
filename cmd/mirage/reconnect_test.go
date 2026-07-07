package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"mirage/internal/protocol"
)

// TestSessionHolderReconnectsAfterDeath drives dial() with a channel so the
// test controls exactly when each attempt resolves -- this lets it assert
// Current()==nil mid-reconnect deterministically instead of racing timers.
func TestSessionHolderReconnectsAfterDeath(t *testing.T) {
	c1, c2 := net.Pipe()
	sess1 := tcpSession{protocol.NewSession(c1)}

	attemptStarted := make(chan struct{})
	result := make(chan error)

	dial := func() (ClientSession, error) {
		attemptStarted <- struct{}{}
		if err := <-result; err != nil {
			return nil, err
		}
		nc1, _ := net.Pipe()
		return tcpSession{protocol.NewSession(nc1)}, nil
	}

	h := newSessionHolder(sess1, dial, nil, time.Millisecond, 5*time.Millisecond)
	defer h.Stop()

	if h.Current() != sess1 {
		t.Fatalf("Current() before death should be the initial session")
	}

	c2.Close() // убивает sess1 -- readLoop получит ошибку чтения

	<-attemptStarted // первая попытка началась
	if cur := h.Current(); cur != nil {
		t.Fatalf("Current() should be nil while reconnecting, got %v", cur)
	}
	result <- errors.New("simulated dial failure")

	<-attemptStarted // вторая попытка
	result <- nil    // на этот раз успех

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur := h.Current(); cur != nil && cur != sess1 {
			return // успех
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("sessionHolder did not install the new session after a successful dial")
}

// TestSessionHolderStopDuringDialDoesNotResurrectSession guards the
// non-blocking-Stop contract: a Stop() that lands after dial() has returned a
// fresh session but before run() publishes it must leave Current()==nil, never
// a live-but-unwatched session.
//
// We drive the interleaving deterministically (no flaky racing, no panic) via
// the onDialReturned test hook, which fires right after dial() returns and, in
// this test, calls Stop() synchronously. Note this guards the CONTRACT, not
// the specific two-vs-one critical-section defect the fix addressed: the fix
// fuses the stop-check and publish into one locked section, removing the gap
// the old bug lived in, so no single seam can reproduce that exact micro-race
// against the shipped code (verified separately by the reviewer's scratch
// replica). What this test does lock in, deterministically and race-clean, is
// that a Stop during reconnect is honored and does not resurrect a session.
func TestSessionHolderStopDuringDialDoesNotResurrectSession(t *testing.T) {
	c1, c2 := net.Pipe()
	sess1 := tcpSession{protocol.NewSession(c1)}

	dial := func() (ClientSession, error) {
		nc1, _ := net.Pipe()
		return tcpSession{protocol.NewSession(nc1)}, nil
	}

	h := newSessionHolder(sess1, dial, nil, time.Millisecond, time.Millisecond)
	// Устанавливаем хук ДО смерти initial-сессии: run() читает onDialReturned
	// только после того, как сработает Done() умершей сессии, а цепочка
	// c2.Close() -> shutdown -> close(closed) -> <-sess.Done() даёт
	// happens-before от этой записи к чтению в run(), так что гонки по полю
	// нет (подтверждается -race).
	h.onDialReturned = func() { h.Stop() }

	c2.Close() // убивает sess1 -- run() уходит в reconnect, dial() вернёт сессию, хук вызовет Stop()

	// Дать run() дойти до решения о публикации и отработать. Stop() уже
	// вызван из хука синхронно внутри run(), так что после короткого отстоя
	// текущей сессии быть не должно.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.Current() == nil {
			select {
			case <-h.stopCh:
				return // Stop() отработал и сессия не воскрешена -- успех
			default:
			}
		}
		time.Sleep(time.Millisecond)
	}
	if cur := h.Current(); cur != nil {
		t.Fatalf("Current() must be nil after Stop() fires in the post-dial pre-publish window, got %v", cur)
	}
}
