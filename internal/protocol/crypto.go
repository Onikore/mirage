package protocol

// crypto.go — набор примитивов и генерация ключей для Noise_NKpsk0
// (см. handshake.go). Само рукопожатие и AEAD-транспорт целиком у
// github.com/flynn/noise — аудированная реализация вместо самодельной.

import (
	"crypto/rand"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

func GenKeypair() (noise.DHKey, error) {
	return cipherSuite.GenerateKeypair(rand.Reader)
}

// DHKeyFromPriv восстанавливает пару ключей из сырого 32-байтового
// приватного ключа (как выдаёт keygen) — публичный выводится из приватного.
func DHKeyFromPriv(priv []byte) (noise.DHKey, error) {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: priv, Public: pub}, nil
}
