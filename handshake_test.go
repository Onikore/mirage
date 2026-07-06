package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
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

	serverSC, consumed, err := serverHandshake(c2, serverKP, psk, newReplayCache(time.Minute))
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

	_, consumed, err := serverHandshake(c2, serverKP, goodPSK, newReplayCache(time.Minute))
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

func TestServerHandshakeRejectsReplay(t *testing.T) {
	serverKP, err := genKeypair()
	if err != nil {
		t.Fatalf("genKeypair: %v", err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)

	// Строим один валидный msg1 напрямую (то же, что делает clientHandshake).
	hs, err := newHandshakeState(true, psk, noise.DHKey{}, serverKP.Public)
	if err != nil {
		t.Fatalf("newHandshakeState: %v", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	mimic, err := buildMimicClientHello("www.google.com", msg1[:32], msg1[32:48])
	if err != nil {
		t.Fatalf("buildMimicClientHello: %v", err)
	}

	rc := newReplayCache(time.Minute)

	// Первая попытка с этими байтами должна пройти.
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		c1.Write(mimic)
		buf := make([]byte, hsMsgLen)
		io.ReadFull(c1, buf) // разблокировать conn.Write(msg2) на сервере
		close(done)
	}()
	if _, _, err := serverHandshake(c2, serverKP, psk, rc); err != nil {
		t.Fatalf("first attempt: expected success, got %v", err)
	}
	c1.Close()
	c2.Close()
	<-done

	// Вторая попытка с ТЕМИ ЖЕ САМЫМИ байтами — должна быть отклонена как replay.
	c3, c4 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		c3.Write(mimic)
		close(done2)
	}()
	_, consumed, err := serverHandshake(c4, serverKP, psk, rc)
	if err == nil {
		t.Fatal("expected replay to be rejected")
	}
	if len(consumed) == 0 {
		t.Fatal("expected consumed bytes for fallback replay")
	}
	c3.Close()
	c4.Close()
	<-done2
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

	_, consumed, err := serverHandshake(c2, serverKP, psk, newReplayCache(time.Minute))
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
