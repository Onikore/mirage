package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
)

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
