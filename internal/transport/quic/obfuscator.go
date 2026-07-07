package quic

import (
	"crypto/rand"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

// ObfuscatedPacketConn wraps a net.PacketConn and encrypts/decrypts all UDP packets
// using ChaCha20Poly1305. The keys are provided dynamically via a callback to support rotation.
// A 12-byte random nonce is prepended to each sent packet.
type ObfuscatedPacketConn struct {
	net.PacketConn
	getPSKs func() [][]byte
}

func NewObfuscatedPacketConn(conn net.PacketConn, getPSKs func() [][]byte) *ObfuscatedPacketConn {
	return &ObfuscatedPacketConn{
		PacketConn: conn,
		getPSKs:    getPSKs,
	}
}

func (c *ObfuscatedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// 2048 is larger than the typical UDP MTU (1500)
	buf := make([]byte, 2048)
	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return n, addr, err
	}

	nonceSize := chacha20poly1305.NonceSize
	if n < nonceSize+16 {
		return 0, addr, errors.New("packet too short")
	}

	nonce := buf[:nonceSize]
	ciphertext := buf[nonceSize:n]

	psks := c.getPSKs()
	for _, psk := range psks {
		if len(psk) != 32 {
			continue
		}
		aead, err := chacha20poly1305.New(psk)
		if err != nil {
			continue
		}
		decrypted, err := aead.Open(p[:0], nonce, ciphertext, nil)
		if err == nil {
			return len(decrypted), addr, nil
		}
	}
	return 0, addr, errors.New("decryption failed")
}

func (c *ObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	psks := c.getPSKs()
	if len(psks) == 0 {
		return 0, errors.New("no psks available")
	}
	psk := psks[0] // Always encrypt with the first (active) PSK
	if len(psk) != 32 {
		return 0, errors.New("invalid psk length")
	}
	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		return 0, err
	}

	nonceSize := aead.NonceSize()
	buf := make([]byte, nonceSize+len(p)+aead.Overhead())
	nonce := buf[:nonceSize]

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}

	aead.Seal(buf[nonceSize:nonceSize], nonce, p, nil)

	if _, err := c.PacketConn.WriteTo(buf, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}
