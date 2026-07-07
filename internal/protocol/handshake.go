package protocol

// handshake.go — рукопожатие Noise_NKpsk0 поверх X25519 (github.com/flynn/noise).
//
// Паттерн NK: статический ключ сервера известен клиенту заранее (как и
// раньше — через server_pub), у клиента своего статического ключа нет
// (общий psk — единственный клиентский credential, как и в прошлой схеме).
//
// psk0, не psk2: с psk2 первое сообщение не зависит от psk вообще — любой,
// кто знает server_pub, получил бы от сервера настоящий ответ, не зная psk.
// Это сломало бы анти-зонд fallback. С psk0 psk подмешивается в самое первое
// сообщение — сервер отклоняет и неверный psk, и мусорные байты уже на нём,
// без паники (проверено).
//
// Wire:
//   msg1 (client->server): мимикрированный TLS ClientHello (см. camouflage.go),
//     несущий 48-байтовое Noise-сообщение (32Б эфемерный pubkey + 16Б AEAD-тег
//     над пустым payload).
//   msg2 (server->client): мимикрированный TLS ServerHello + продолжающая
//     запись (см. servhello.go), несущие те же 48 байт (32Б эфемерный pubkey
//     + 16Б AEAD-тег).

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/flynn/noise"
)

var errAuth = errors.New("mirage: handshake auth failed")
var errReplay = errors.New("mirage: replayed handshake")

func newHandshakeState(initiator bool, psk []byte, staticKP noise.DHKey, peerStatic []byte) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:           cipherSuite,
		Pattern:               noise.HandshakeNK,
		Initiator:             initiator,
		PresharedKey:          psk,
		PresharedKeyPlacement: 0,
		StaticKeypair:         staticKP,
		PeerStatic:            peerStatic,
	})
}

// ClientHandshake выполняет рукопожатие и возвращает защищённый канал.
func ClientHandshake(conn net.Conn, serverPub, psk []byte, sni string) (*SecureConn, error) {
	hs, err := newHandshakeState(true, psk, noise.DHKey{}, serverPub)
	if err != nil {
		return nil, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	ecPub, tag1 := msg1[:32], msg1[32:48]
	mimic, err := buildMimicClientHello(sni, ecPub, tag1)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(mimic); err != nil {
		return nil, err
	}

	esPub, tag2, err := parseRealityServerHello(conn)
	if err != nil {
		return nil, errAuth
	}
	buf := append(append([]byte(nil), esPub...), tag2...)
	_, csC2S, csS2C, err := hs.ReadMessage(nil, buf)
	if err != nil {
		return nil, errAuth
	}

	// клиент пишет c2s, читает s2c
	sc := newSecureConn(conn, csC2S, csS2C)
	sc.tlsFraming = true
	return sc, nil
}

// ServerHandshake пытается принять клиента. Всегда возвращает consumed —
// байты, уже прочитанные из conn, чтобы caller мог их переиграть в fallback.
// psks — набор одновременно валидных psk (см. pskset.go): пробуем каждый по
// очереди, пока один не подойдёт — так старый и новый psk работают
// параллельно на время ротации. rc — общий на процесс анти-replay кэш
// (см. replay.go); проверяется только после успешной аутентификации, чтобы
// мусор его не засорял.
func ServerHandshake(conn net.Conn, kps []noise.DHKey, psks [][]byte, rc *ReplayCache, proxyDial func() (net.Conn, error)) (sc *SecureConn, consumed []byte, err error) {
	ecPub, tag1, _, consumed, perr := parseMimicClientHello(conn)
	if perr != nil {
		return nil, consumed, perr
	}
	msg1 := append(append([]byte(nil), ecPub...), tag1...)

	var hs *noise.HandshakeState
	for _, kp := range kps {
		for _, psk := range psks {
			candidate, herr := newHandshakeState(false, psk, kp, nil)
			if herr != nil {
				continue
			}
			if _, _, _, e := candidate.ReadMessage(nil, msg1); e == nil {
				hs = candidate
				break
			}
		}
		if hs != nil {
			break
		}
	}
	if hs == nil {
		return nil, consumed, errAuth // зонд / мусор / ни один psk не подошёл -> fallback
	}

	if rc.checkAndRemember(ecPub) {
		return nil, consumed, errReplay // повтор ранее принятого msg1 -> fallback
	}

	msg2, csC2S, csS2C, e := hs.WriteMessage(nil, nil)
	if e != nil {
		return nil, consumed, e
	}
	esPub := msg2[:32]
	tag2 := msg2[32:48]

	destConn, err := proxyDial()
	if err != nil {
		return nil, consumed, err
	}
	defer destConn.Close()

	destConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := destConn.Write(consumed); err != nil {
		return nil, consumed, err
	}

	destConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	modHello, err := proxyServerHello(destConn, esPub, tag2)
	if err != nil {
		return nil, consumed, err
	}
	if _, err := conn.Write(modHello); err != nil {
		return nil, consumed, err
	}

	destConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(destConn, hdr); err != nil {
			break
		}
		length := binary.BigEndian.Uint16(hdr[3:5])
		body := make([]byte, length)
		if _, err := io.ReadFull(destConn, body); err != nil {
			break
		}
		conn.Write(hdr)
		conn.Write(body)
	}

	sc = newSecureConn(conn, csS2C, csC2S)
	sc.tlsFraming = true
	return sc, consumed, nil
}
