package main

import (
	"net"
	"testing"
	"time"

	"mirage/internal/protocol"
)

// runClientListener must return promptly once its listener is closed — this
// is exactly the contract the GUI's "Disconnect" button relies on.
func TestRunClientListenerReturnsWhenListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c1, _ := net.Pipe()
	sess := protocol.NewSession(c1)

	done := make(chan struct{})
	go func() {
		runClientListener(ln, sess)
		close(done)
	}()

	ln.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runClientListener did not return after listener was closed")
	}
}
