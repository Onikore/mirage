package main

// crypto.go — примитивы. Только stdlib.
// В ПРОДЕ: замени рукопожатие на полноценный Noise (flynn/noise или snow).
// Здесь — педагогический, но криптографически корректный минимум:
//   X25519 (crypto/ecdh) + HKDF-SHA256 + AES-256-GCM.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

var curve = ecdh.X25519()

func genKey() (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand.Reader)
}

// ecdhShared: X25519(priv, pubBytes) -> общий секрет.
func ecdhShared(priv *ecdh.PrivateKey, pubBytes []byte) ([]byte, error) {
	pub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// --- HKDF-SHA256 (RFC 5869), руками на hmac ---

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n)
	var t []byte
	var counter byte = 1
	for len(out) < n {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:n]
}

// --- AEAD ---

func newAEAD(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key) // 32B -> AES-256
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// nonce12: 96-битный nonce из счётчика (big-endian в младших 8 байтах).
func nonce12(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
