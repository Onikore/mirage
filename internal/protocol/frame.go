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
	conn net.Conn
	wCS  *noise.CipherState
	rCS  *noise.CipherState
	rbuf []byte // остаток расшифрованного, ещё не отданный в Read
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

func (s *SecureConn) Read(p []byte) (int, error) {
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
		pt, err := s.rCS.Decrypt(nil, nil, ct)
		if err != nil {
			return 0, err
		}
		s.rbuf = pt
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *SecureConn) Close() error { return s.conn.Close() }
