package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestDroppedOpenIsNotRegistered guards against a leak found in final
// review: when acceptCh's backlog is full, the OPEN frame handler must drop
// the new stream WITHOUT registering it in s.streams. The earlier version
// registered it unconditionally before attempting the enqueue -- a stream
// left registered but never Accept()-ed would sit in the map forever, and
// once its readCh (cap 64) filled with subsequent DATA frames, readLoop
// would block trying to deliver the 65th, stalling every other stream on
// the session, not just the dropped one. An unbuffered acceptCh with no
// waiting receiver deterministically hits the drop path, so this is
// reproduced directly rather than via timing.
func TestDroppedOpenIsNotRegistered(t *testing.T) {
	s := &Session{
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream), // unbuffered -- always drops without a waiting Accept()
		closed:   make(chan struct{}),
	}

	st := s.buildStream(1)
	st.openPayload = []byte("x")
	select {
	case s.acceptCh <- st:
		t.Fatal("unexpected: send succeeded on an unbuffered channel with no receiver")
	default:
		// expected -- this is the drop path
	}

	s.mu.Lock()
	_, registered := s.streams[1]
	s.mu.Unlock()
	if registered {
		t.Fatal("dropped stream must not be registered in s.streams -- this is exactly the leak/deadlock bug")
	}
}

func TestSessionConcurrentStreams(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1)
	server := NewSession(c2)

	const nStreams = 5
	var wg sync.WaitGroup

	go func() {
		for i := 0; i < nStreams; i++ {
			st, payload, err := server.Accept()
			if err != nil {
				return
			}
			go func(st *Stream, payload []byte) {
				buf := make([]byte, 64)
				n, err := st.Read(buf)
				if err != nil {
					return
				}
				reply := append([]byte("echo("), payload...)
				reply = append(reply, []byte("):")...)
				reply = append(reply, buf[:n]...)
				st.Write(reply)
			}(st, payload)
		}
	}()

	results := make([][]byte, nStreams)
	for i := 0; i < nStreams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := []byte(fmt.Sprintf("target-%d", i))
			st, err := client.Open(target)
			if err != nil {
				t.Errorf("Open: %v", err)
				return
			}
			msg := []byte(fmt.Sprintf("hello-%d", i))
			if _, err := st.Write(msg); err != nil {
				t.Errorf("Write: %v", err)
				return
			}
			buf := make([]byte, 128)
			n, err := st.Read(buf)
			if err != nil {
				t.Errorf("Read: %v", err)
				return
			}
			results[i] = append([]byte(nil), buf[:n]...)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		want := []byte(fmt.Sprintf("echo(target-%d):hello-%d", i, i))
		if !bytes.Equal(r, want) {
			t.Errorf("stream %d: got %q want %q", i, r, want)
		}
	}
}

// TestReadDrainsBufferedDataBeforeRemoteClose deterministically reconstructs
// the exact state that caused data loss on real traffic during manual
// verification: a stream has one already-buffered-but-unread data frame at
// the moment readLoop processes that stream's CLOSE frame. Constructed
// directly (no network, no goroutine timing) because reproducing the race
// through net.Pipe turned out to be unreliable -- net.Pipe's synchronous,
// unbuffered handoff keeps the writer in lockstep with readLoop, which
// prevented the race from manifesting even against the old, buggy
// implementation. Real TCP (used in manual verification with actual HTTP
// traffic) lets the OS buffer the DATA and CLOSE frames together, letting
// readLoop race ahead of the consumer -- which is what exposed the bug.
func TestReadDrainsBufferedDataBeforeRemoteClose(t *testing.T) {
	st := &Stream{
		readCh:    make(chan []byte, 4),
		abandonCh: make(chan struct{}),
	}
	want := []byte("final-chunk")
	st.readCh <- want // data already arrived and is sitting in the buffer
	st.closeReadCh()  // readLoop then processes that stream's CLOSE frame

	buf := make([]byte, len(want))
	n, err := io.ReadFull(st, buf)
	if err != nil {
		t.Fatalf("ReadFull: %v (got %d/%d bytes: %q)", err, n, len(want), buf[:n])
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("got %q, want %q", buf, want)
	}

	if _, err := st.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read after drain: err=%v, want io.EOF", err)
	}
}

func TestStreamCloseYieldsEOF(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1)
	server := NewSession(c2)

	st, err := client.Open([]byte("x"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, _, err := server.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := st.Read(buf); err != io.EOF {
		t.Errorf("Read after close: err=%v, want io.EOF", err)
	}
}

func TestSessionDoneAndErr(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession(c1)

	select {
	case <-sess.Done():
		t.Fatal("Done() closed before the session died")
	default:
	}
	if err := sess.Err(); err != nil {
		t.Fatalf("Err() should be nil while alive, got %v", err)
	}

	c2.Close()

	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() did not close after the underlying connection closed")
	}
	if sess.Err() == nil {
		t.Fatal("Err() should be non-nil after the session died")
	}
}

func TestSessionClose(t *testing.T) {
	c1, _ := net.Pipe()
	sess := NewSession(c1)

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() did not close after Close()")
	}
}

func TestPaddingFramesNeverReachApplicationStream(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1)
	server := NewSession(c2)
	server.StartPadding(1*time.Millisecond, 3*time.Millisecond, 8, 16)
	client.StartPadding(1*time.Millisecond, 3*time.Millisecond, 8, 16)

	clientSt, err := client.Open([]byte("target"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	serverSt, _, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	want := []byte("real application data")
	go func() {
		time.Sleep(20 * time.Millisecond) // let a few padding frames interleave first
		serverSt.Write(want)
	}()

	buf := make([]byte, len(want))
	if _, err := io.ReadFull(clientSt, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("got %q, want %q -- a padding frame's bytes leaked into the application stream", buf, want)
	}
}
