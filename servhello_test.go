package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMimicServerHelloRoundTrip(t *testing.T) {
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	esPub := make([]byte, 32)
	rand.Read(esPub)
	tag2 := make([]byte, 16)
	rand.Read(tag2)

	raw, err := buildMimicServerHello(sessionID, esPub, tag2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	gotPub, gotTag, err := parseMimicServerHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(gotPub, esPub) {
		t.Errorf("esPub mismatch: got %x want %x", gotPub, esPub)
	}
	if !bytes.Equal(gotTag, tag2) {
		t.Errorf("tag2 mismatch: got %x want %x", gotTag, tag2)
	}
}

func TestBuildMimicServerHelloRejectsBadLengths(t *testing.T) {
	sessionID := make([]byte, 32)
	if _, err := buildMimicServerHello(sessionID, make([]byte, 31), make([]byte, 16)); err == nil {
		t.Fatal("expected error for wrong-length esPub")
	}
	if _, err := buildMimicServerHello(sessionID, make([]byte, 32), make([]byte, 15)); err == nil {
		t.Fatal("expected error for wrong-length tag2")
	}
}

func TestParseMimicServerHelloRejectsGarbage(t *testing.T) {
	if _, _, err := parseMimicServerHello(bytes.NewReader([]byte("not a tls record at all"))); err == nil {
		t.Fatal("expected error for non-TLS input")
	}
}
