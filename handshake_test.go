package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestHandshakeRoundTrip(t *testing.T) {
	serverKP, err := genKeypair()
	if err != nil {
		t.Fatalf("genKeypair: %v", err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)

	c1, c2 := net.Pipe()

	type clientResult struct {
		sc  *secureConn
		err error
	}
	clientCh := make(chan clientResult, 1)
	go func() {
		sc, err := clientHandshake(c1, serverKP.Public, psk, "www.google.com")
		clientCh <- clientResult{sc, err}
	}()

	serverSC, consumed, err := serverHandshake(c2, serverKP, psk)
	if err != nil {
		t.Fatalf("serverHandshake: %v (consumed %d bytes)", err, len(consumed))
	}

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("clientHandshake: %v", cr.err)
	}

	msg1 := []byte("hello from client")
	go cr.sc.Write(msg1)
	buf1 := make([]byte, len(msg1))
	if _, err := io.ReadFull(serverSC, buf1); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf1, msg1) {
		t.Errorf("server got %q, want %q", buf1, msg1)
	}

	msg2 := []byte("hello from server")
	go serverSC.Write(msg2)
	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(cr.sc, buf2); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf2, msg2) {
		t.Errorf("client got %q, want %q", buf2, msg2)
	}
}

func TestServerHandshakeRejectsBadPSK(t *testing.T) {
	serverKP, err := genKeypair()
	if err != nil {
		t.Fatalf("genKeypair: %v", err)
	}
	goodPSK := make([]byte, 32)
	rand.Read(goodPSK)
	badPSK := make([]byte, 32)
	rand.Read(badPSK)

	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		clientHandshake(c1, serverKP.Public, badPSK, "www.google.com")
		close(done)
	}()

	_, consumed, err := serverHandshake(c2, serverKP, goodPSK)
	if err == nil {
		t.Fatal("expected error for bad psk")
	}
	if len(consumed) == 0 {
		t.Fatal("expected consumed bytes for fallback replay")
	}

	c1.Close()
	c2.Close()
	<-done
}

func TestServerHandshakeRejectsGarbage(t *testing.T) {
	serverKP, err := genKeypair()
	if err != nil {
		t.Fatalf("genKeypair: %v", err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)

	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		c1.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		close(done)
	}()

	_, consumed, err := serverHandshake(c2, serverKP, psk)
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	if len(consumed) == 0 {
		t.Fatal("expected consumed bytes for fallback replay")
	}

	c1.Close()
	c2.Close()
	<-done
}
