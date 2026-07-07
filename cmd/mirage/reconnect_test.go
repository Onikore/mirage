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
// non-blocking-Stop design: Disconnect while a redial is in flight must not
// let that redial's result become the current session afterward.
func TestSessionHolderStopDuringDialDoesNotResurrectSession(t *testing.T) {
	c1, c2 := net.Pipe()
	sess1 := protocol.NewSession(c1)

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})

	dial := func() (*protocol.Session, error) {
		close(dialStarted)
		<-releaseDial
		nc1, _ := net.Pipe()
		return protocol.NewSession(nc1), nil
	}

	h := newSessionHolder(sess1, dial, nil, time.Millisecond, time.Millisecond)
	c2.Close() // убивает sess1 -- запускает dial()

	<-dialStarted
	h.Stop() // Disconnect ровно во время dial()
	close(releaseDial) // теперь dial() вернёт успех

	time.Sleep(20 * time.Millisecond) // дать run() шанс (ошибочно) установить сессию
	if cur := h.Current(); cur != nil {
		t.Fatalf("Current() should stay nil after Stop() during an in-flight dial, got %v", cur)
	}
}
