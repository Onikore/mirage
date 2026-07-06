package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMimicClientHelloRoundTrip(t *testing.T) {
	ecPub := make([]byte, 32)
	rand.Read(ecPub)
	tag1 := make([]byte, 16)
	rand.Read(tag1)

	raw, err := buildMimicClientHello("www.google.com", ecPub, tag1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	gotPub, gotTag, consumed, err := parseMimicClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(gotPub, ecPub) {
		t.Errorf("ecPub mismatch: got %x want %x", gotPub, ecPub)
	}
	if !bytes.Equal(gotTag, tag1) {
		t.Errorf("tag1 mismatch: got %x want %x", gotTag, tag1)
	}
	if len(consumed) != len(raw) {
		t.Errorf("consumed %d bytes, want %d (full record)", len(consumed), len(raw))
	}
}

func TestParseMimicClientHelloGarbage(t *testing.T) {
	in := []byte("GET / HTTP/1.1\r\n")
	_, _, consumed, err := parseMimicClientHello(bytes.NewReader(in))
	if err == nil {
		t.Fatal("expected error for non-TLS input")
	}
	if !bytes.Equal(consumed, in[:5]) {
		t.Errorf("consumed = % x, want exactly the 5-byte record header % x", consumed, in[:5])
	}
}

func TestParseMimicClientHelloShortRead(t *testing.T) {
	// Prober sends 2 bytes then closes the connection (EOF).
	in := []byte{0x16, 0x03}
	_, _, consumed, err := parseMimicClientHello(bytes.NewReader(in))
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
	if !bytes.Equal(consumed, in) {
		t.Errorf("consumed = % x, want exactly % x (no zero-padding)", consumed, in)
	}
}
