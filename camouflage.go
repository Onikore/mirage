package main

// camouflage.go — обёртка client->server рукопожатия в мимикрированный
// TLS 1.3 ClientHello (fingerprint Chrome, через uTLS), чтобы первый байт
// на проводе не палился энтропийным/форматным детектором как "голый" X25519.
//
// Наш X25519 ephemeral pubkey едет как есть в key_share-расширении (формат
// совпадает 1-в-1, отдельного поля не нужно). AEAD-тег рукопожатия (tag1,
// 16 байт) едет в session_id — поле, которое настоящий Chrome и так
// заполняет случайными 32 байтами для совместимости с middlebox'ами, так
// что по байтам неотличимо.
//
// parseMimicClientHello также возвращает полный session_id клиента (32Б) —
// сервер обязан эхом вернуть его в своём ServerHello (см. servhello.go),
// иначе пассивный наблюдатель, сверяющий session_id между двумя половинами
// хендшейка, увидел бы несоответствие с настоящим TLS 1.3.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	tls "github.com/refraction-networking/utls"
)

const maxMimicHelloLen = 8192

func buildMimicClientHello(sni string, ecPub, tag1 []byte) ([]byte, error) {
	if len(ecPub) != 32 || len(tag1) != 16 {
		return nil, errors.New("mirage: buildMimicClientHello: ecPub must be 32 bytes, tag1 must be 16 bytes")
	}
	uconn := tls.UClient(nil, &tls.Config{ServerName: sni}, tls.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uconn.HandshakeState.Hello

	found := false
	for i := range hello.KeyShares {
		if hello.KeyShares[i].Group == tls.X25519 {
			hello.KeyShares[i].Data = ecPub
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("mirage: chrome fingerprint has no x25519 key share")
	}

	sessionID := make([]byte, 32)
	copy(sessionID, tag1)
	if _, err := rand.Read(sessionID[len(tag1):]); err != nil {
		return nil, err
	}
	hello.SessionId = sessionID

	hello.Raw = nil // force re-marshal: Marshal() returns stale .Raw bytes otherwise
	body, err := hello.Marshal()
	if err != nil {
		return nil, err
	}

	record := make([]byte, 5+len(body))
	record[0] = 0x16                  // handshake content type
	record[1], record[2] = 0x03, 0x01 // legacy record version; real TLS1.3 clients send this too
	binary.BigEndian.PutUint16(record[3:5], uint16(len(body)))
	copy(record[5:], body)
	return record, nil
}

// parseMimicClientHello reads one mimicked ClientHello record from r.
// consumed always holds every byte actually read, even on error, so the
// caller's anti-probe fallback can replay exactly what a prober sent.
func parseMimicClientHello(r io.Reader) (ecPub, tag1, sessionID, consumed []byte, err error) {
	hdr := make([]byte, 5)
	nHdr, hdrErr := io.ReadFull(r, hdr)
	consumed = append(consumed, hdr[:nHdr]...)
	if hdrErr != nil {
		return nil, nil, nil, consumed, hdrErr
	}
	if hdr[0] != 0x16 {
		return nil, nil, nil, consumed, errors.New("mirage: not a handshake record")
	}
	n := binary.BigEndian.Uint16(hdr[3:5])
	if n == 0 || n > maxMimicHelloLen {
		return nil, nil, nil, consumed, errors.New("mirage: implausible client hello length")
	}
	body := make([]byte, n)
	nBody, bodyErr := io.ReadFull(r, body)
	consumed = append(consumed, body[:nBody]...)
	if bodyErr != nil {
		return nil, nil, nil, consumed, bodyErr
	}

	hello := tls.UnmarshalClientHello(body)
	if hello == nil {
		return nil, nil, nil, consumed, errors.New("mirage: not a valid client hello")
	}
	if len(hello.SessionId) < 16 {
		return nil, nil, nil, consumed, errors.New("mirage: session id too short")
	}
	sessionID = hello.SessionId
	tag1 = hello.SessionId[:16]

	for _, ks := range hello.KeyShares {
		if ks.Group == tls.X25519 && len(ks.Data) == 32 {
			ecPub = ks.Data
			break
		}
	}
	if ecPub == nil {
		return nil, nil, nil, consumed, errors.New("mirage: no x25519 key share")
	}
	return ecPub, tag1, sessionID, consumed, nil
}
