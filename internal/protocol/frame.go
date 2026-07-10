package protocol

// frame.go — потоковый AEAD-канал поверх net.Conn.
// Каждый Write режется на записи <=16 KiB, каждая запечатывается AEAD.
// Wire записи: len(u16 BE) || ciphertext(len)   ; nonce ведёт сам noise.CipherState.
//
// Реализует io.ReadWriteCloser -> совместим с io.Copy для релея.
//
// ТУТ хук для chameleon-shaping: перед Write можно добавлять PADDING-записи
// и подгонять размеры под целевой профиль трафика (см. writeShaped, TODO).

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/flynn/noise"
)

const maxPlain = 16384

type SecureConn struct {
	conn           net.Conn
	wCS            *noise.CipherState
	rCS            *noise.CipherState
	rbuf           []byte // остаток расшифрованного, ещё не отданный в Read
	tlsFraming     bool
	seenValidFrame bool
}

func newSecureConn(conn net.Conn, writeCS, readCS *noise.CipherState) *SecureConn {
	return &SecureConn{conn: conn, wCS: writeCS, rCS: readCS}
}

func (s *SecureConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlain {
			chunk = p[:maxPlain]
		}
		ct, err := s.wCS.Encrypt(nil, nil, chunk)
		if err != nil {
			return total, err
		}

		var frame []byte
		if s.tlsFraming {
			frame = make([]byte, 5+len(ct))
			frame[0] = 0x17                 // application_data
			frame[1], frame[2] = 0x03, 0x03 // TLS 1.2/1.3
			binary.BigEndian.PutUint16(frame[3:5], uint16(len(ct)))
			copy(frame[5:], ct)
		} else {
			frame = make([]byte, 2+len(ct))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(ct)))
			copy(frame[2:], ct)
		}

		if _, err := s.conn.Write(frame); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *SecureConn) Read(p []byte) (int, error) {
	for len(s.rbuf) == 0 {
		var n uint16
		var hdrType byte
		if s.tlsFraming {
			var hdr [5]byte
			if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
				return 0, err
			}
			hdrType = hdr[0]
			n = binary.BigEndian.Uint16(hdr[3:5])
		} else {
			var hdr [2]byte
			if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
				return 0, err
			}
			n = binary.BigEndian.Uint16(hdr[:])
		}

		ct := make([]byte, n)
		if _, err := io.ReadFull(s.conn, ct); err != nil {
			return 0, err
		}

		if s.tlsFraming {
			if hdrType == 0x14 { // ChangeCipherSpec
				continue
			}
			if hdrType != 0x17 { // Not ApplicationData
				continue
			}
		}

		pt, err := s.rCS.Decrypt(nil, nil, ct)
		if err != nil {
			if s.tlsFraming && !s.seenValidFrame {
				// В Reality-режиме это может быть сертификат реального сайта.
				// Пропускаем записи, пока не сможем расшифровать нашу.
				continue
			}
			return 0, err
		}
		s.seenValidFrame = true
		s.rbuf = pt
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *SecureConn) Close() error { return s.conn.Close() }
