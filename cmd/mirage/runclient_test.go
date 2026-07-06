package main

import (
	"net"
	"testing"
	"time"
)

// runClientListener must return promptly once its listener is closed — this
// is exactly the contract the GUI's "Disconnect" button relies on.
func TestRunClientListenerReturnsWhenListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		runClientListener(ln, "127.0.0.1:1", nil, nil, "")
		close(done)
	}()

	ln.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runClientListener did not return after listener was closed")
	}
}
