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
	sess1 := protocol.NewSession(c1)

	attemptStarted := make(chan struct{})
	result := make(chan error)

	dial := func() (*protocol.Session, error) {
		attemptStarted <- struct{}{}
		if err := <-result; err != nil {
			return nil, err
		}
		nc1, _ := net.Pipe()
		return protocol.NewSession(nc1), nil
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
	result <- nil // на этот раз успех

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
// non-blocking-Stop design: a Disconnect that races the *publish* of a
// just-returned redial must never leave a live session installed afterward.
//
// The earlier version of this test blocked dial() until Stop() had fully
// returned, so run() always observed stopCh already closed at the post-dial
// select and the real publish-after-Stop window was never exercised. Here
// dial() RETURNS IMMEDIATELY and signals just before returning; the test then
// races h.Stop() against run()'s post-dial stop-check-and-publish. Looping
// many iterations drives enough interleavings that the separate-critical-
// sections layout (stop-check and publish under different locks) leaks a live
// session -- Current() != nil after Stop() -- while the single-lock fix keeps
// Current() reliably nil.
func TestSessionHolderStopDuringDialDoesNotResurrectSession(t *testing.T) {
	for i := 0; i < 300; i++ {
		c1, c2 := net.Pipe()
		sess1 := protocol.NewSession(c1)

		dialReturning := make(chan struct{})
		dial := func() (*protocol.Session, error) {
			nc1, _ := net.Pipe()
			close(dialReturning) // сигнал: dial сейчас же вернёт новую сессию
			return protocol.NewSession(nc1), nil
		}

		h := newSessionHolder(sess1, dial, nil, time.Millisecond, time.Millisecond)
		c2.Close() // убивает sess1 -- запускает dial()

		<-dialReturning // dial() вот-вот вернёт сессию: гонимся Stop() с публикацией
		h.Stop()

		// После возврата Stop() (и короткого отстоя, чтобы дать проигравшей
		// гонку горутине run() шанс ошибочно опубликовать) текущей сессии быть
		// не должно: либо Stop() выиграл гонку, либо run() увидел закрытый
		// stopCh под тем же замком и отказался публиковать.
		time.Sleep(time.Millisecond)
		if cur := h.Current(); cur != nil {
			t.Fatalf("iter %d: Current() must be nil after Stop() races an in-flight dial's publish, got %v", i, cur)
		}
	}
}
