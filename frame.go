package main

// frame.go — потоковый AEAD-канал поверх net.Conn.
// Каждый Write режется на записи <=16 KiB, каждая запечатывается GCM.
// Wire записи: len(u16 BE) || ciphertext(len)   ; nonce = счётчик направления.
//
// Реализует io.ReadWriteCloser -> совместим с io.Copy для релея.
//
// ТУТ хук для chameleon-shaping: перед Write можно добавлять PADDING-записи
// и подгонять размеры под целевой профиль трафика (см. writeShaped, TODO).

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
)

const maxPlain = 16384

type secureConn struct {
	conn  net.Conn
	wAEAD cipher.AEAD
	rAEAD cipher.AEAD
	wSeq  uint64
	rSeq  uint64
	rbuf  []byte // остаток расшифрованного, ещё не отданный в Read
}

func newSecureConn(conn net.Conn, writeKey, readKey []byte) *secureConn {
	return &secureConn{
		conn:  conn,
		wAEAD: newAEAD(writeKey),
		rAEAD: newAEAD(readKey),
		wSeq:  1, // 0 зарезервирован
		rSeq:  1,
	}
}

func (s *secureConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlain {
			chunk = p[:maxPlain]
		}
		ct := s.wAEAD.Seal(nil, nonce12(s.wSeq), chunk, nil)
		s.wSeq++
		frame := make([]byte, 2+len(ct))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(ct)))
		copy(frame[2:], ct)
		if _, err := s.conn.Write(frame); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *secureConn) Read(p []byte) (int, error) {
	if len(s.rbuf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint16(hdr[:])
		ct := make([]byte, n)
		if _, err := io.ReadFull(s.conn, ct); err != nil {
			return 0, err
		}
		pt, err := s.rAEAD.Open(nil, nonce12(s.rSeq), ct, nil)
		if err != nil {
			return 0, err
		}
		s.rSeq++
		s.rbuf = pt
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *secureConn) Close() error { return s.conn.Close() }
