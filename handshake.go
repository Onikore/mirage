package main

// handshake.go — 2-сообщенийное рукопожатие поверх X25519.
//
// Свойства (для скелета достаточно, для прода — Noise):
//   * конфиденциальность и forward secrecy: эфемерали с обеих сторон (es + ee)
//   * аутентификация клиента: PSK вплетён в ключ рукопожатия
//   * аутентификация сервера: клиент шифрует на статический pub сервера
//   * анти-зонд: без верного PSK тег не проходит Open() -> сервер уводит в fallback
//
// Wire:
//   msg1 (client->server): mimicked TLS 1.3 ClientHello (Chrome fingerprint,
//     see camouflage.go) carrying e_pub_c in its key_share extension and
//     tag1 in its session_id.  tag1 = AEAD(k1, n=0, "", ad=e_pub_c)
//   msg2 (server->client): e_pub_s(32) || tag2(16)   tag2 = AEAD(k1, n=1, "", ad=e_pub_s)
//     (raw, not TLS-framed — see README "Что дальше" for the remaining gap)
//   k1 = HKDF( extract(PSK, es), "mirage-v0 hs" )
//   master = extract(PSK, es||ee); k_c2s/k_s2c = HKDF(master, label||e_pub_c||e_pub_s)

import (
	"crypto/ecdh"
	"errors"
	"io"
	"net"
)

const (
	hsMsgLen = 32 + 16 // pub + tag
)

var errAuth = errors.New("mirage: handshake auth failed")

var (
	labelHS  = []byte("mirage-v0 hs")
	labelC2S = []byte("mirage-v0 c2s")
	labelS2C = []byte("mirage-v0 s2c")
)

// clientHandshake выполняет рукопожатие и возвращает защищённый канал.
func clientHandshake(conn net.Conn, serverPub, psk []byte, sni string) (*secureConn, error) {
	ec, err := genKey()
	if err != nil {
		return nil, err
	}
	ecPub := ec.PublicKey().Bytes()

	es, err := ecdhShared(ec, serverPub)
	if err != nil {
		return nil, err
	}
	k1 := hkdfExpand(hkdfExtract(psk, es), labelHS, 32)
	a := newAEAD(k1)

	tag1 := a.Seal(nil, nonce12(0), nil, ecPub)
	msg1, err := buildMimicClientHello(sni, ecPub, tag1)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg1); err != nil {
		return nil, err
	}

	buf := make([]byte, hsMsgLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	esPub, tag2 := buf[:32], buf[32:48]
	if _, err := a.Open(nil, nonce12(1), tag2, esPub); err != nil {
		return nil, errAuth
	}

	ee, err := ecdhShared(ec, esPub)
	if err != nil {
		return nil, err
	}
	master := hkdfExtract(psk, concat(es, ee))
	kc2s := hkdfExpand(master, concat(labelC2S, ecPub, esPub), 32)
	ks2c := hkdfExpand(master, concat(labelS2C, ecPub, esPub), 32)

	// клиент пишет c2s, читает s2c
	return newSecureConn(conn, kc2s, ks2c), nil
}

// serverHandshake пытается принять клиента. Всегда возвращает consumed —
// байты, уже прочитанные из conn, чтобы caller мог их переиграть в fallback.
func serverHandshake(conn net.Conn, priv *ecdh.PrivateKey, psk []byte) (sc *secureConn, consumed []byte, err error) {
	ecPub, tag1, consumed, perr := parseMimicClientHello(conn)
	if perr != nil {
		return nil, consumed, perr
	}

	es, e := ecdhShared(priv, ecPub)
	if e != nil {
		return nil, consumed, errAuth
	}
	k1 := hkdfExpand(hkdfExtract(psk, es), labelHS, 32)
	a := newAEAD(k1)
	if _, e := a.Open(nil, nonce12(0), tag1, ecPub); e != nil {
		return nil, consumed, errAuth // зонд / мусор -> fallback
	}

	// клиент аутентифицирован — отвечаем эфемералью
	esKey, e := genKey()
	if e != nil {
		return nil, consumed, e
	}
	esPub := esKey.PublicKey().Bytes()
	tag2 := a.Seal(nil, nonce12(1), nil, esPub)
	if _, e := conn.Write(concat(esPub, tag2)); e != nil {
		return nil, consumed, e
	}

	ee, e := ecdhShared(esKey, ecPub)
	if e != nil {
		return nil, consumed, e
	}
	master := hkdfExtract(psk, concat(es, ee))
	kc2s := hkdfExpand(master, concat(labelC2S, ecPub, esPub), 32)
	ks2c := hkdfExpand(master, concat(labelS2C, ecPub, esPub), 32)

	// сервер читает c2s, пишет s2c
	return newSecureConn(conn, ks2c, kc2s), consumed, nil
}
