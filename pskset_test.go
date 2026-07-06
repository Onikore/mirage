package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func writeTempPSKFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "psks.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp psk file: %v", err)
	}
	return path
}

func randHexPSK() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func TestLoadPSKFileParsesKeysSkipsCommentsAndBlanks(t *testing.T) {
	a, b := randHexPSK(), randHexPSK()
	path := writeTempPSKFile(t, "# comment\n\n"+a+"\n"+b+"\n")

	keys, err := loadPSKFile(path)
	if err != nil {
		t.Fatalf("loadPSKFile: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	wantA, _ := hex.DecodeString(a)
	wantB, _ := hex.DecodeString(b)
	if !bytes.Equal(keys[0], wantA) || !bytes.Equal(keys[1], wantB) {
		t.Errorf("keys don't match input")
	}
}

func TestLoadPSKFileRejectsWrongLength(t *testing.T) {
	path := writeTempPSKFile(t, "aabbcc\n")
	if _, err := loadPSKFile(path); err == nil {
		t.Fatal("expected error for short psk")
	}
}

func TestLoadPSKFileRejectsEmpty(t *testing.T) {
	path := writeTempPSKFile(t, "# only comments\n\n")
	if _, err := loadPSKFile(path); err == nil {
		t.Fatal("expected error for file with no psks")
	}
}

func TestPSKSetStoreLoadIsAtomic(t *testing.T) {
	a := make([]byte, 32)
	rand.Read(a)
	b := make([]byte, 32)
	rand.Read(b)

	s := newPSKSet([][]byte{a})
	got := s.Load()
	if len(got) != 1 || !bytes.Equal(got[0], a) {
		t.Fatalf("initial Load() = %v, want [%x]", got, a)
	}

	s.Store([][]byte{b})
	got = s.Load()
	if len(got) != 1 || !bytes.Equal(got[0], b) {
		t.Fatalf("Load() after Store() = %v, want [%x]", got, b)
	}
}
