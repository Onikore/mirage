package socks

// socks.go — минимальный SOCKS5 (no-auth) как локальный вход клиента.
// Accept парсит и CONNECT, и UDP ASSOCIATE на уровне протокола, но
// вызывающий код (clientConn в cmd/mirage/main.go) сейчас поддерживает
// только CONNECT -- UDP ASSOCIATE отклоняется явным SOCKS5-ответом, а не
// молча проксируется без защиты (см. main.go для причины).

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Accept разбирает SOCKS5 запрос и возвращает cmd, host, port.
func Accept(c net.Conn) (byte, string, uint16, error) {
	// greeting: ver, nmethods, methods...
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, "", 0, err
	}
	if head[0] != 0x05 {
		return 0, "", 0, errors.New("socks: not v5")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return 0, "", 0, err
	}
	// no-auth
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return 0, "", 0, err
	}

	// request: ver cmd rsv atyp ...
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return 0, "", 0, err
	}
	if req[1] != 0x01 && req[1] != 0x03 { // CONNECT or UDP ASSOCIATE
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 0, "", 0, errors.New("socks: unsupported cmd")
	}
	cmd := req[1]

	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		b := make([]byte, l[0])
		io.ReadFull(c, b)
		host = string(b)
	default:
		return 0, "", 0, errors.New("socks: bad atyp")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return 0, "", 0, err
	}
	port := binary.BigEndian.Uint16(pb)

	return cmd, host, port, nil
}

// SendSuccessReply отправляет SOCKS5 ответ об успешном выполнении с указанием привязанного IP и порта.
func SendSuccessReply(c net.Conn, ip net.IP, port uint16) error {
	rep := []byte{0x05, 0x00, 0x00, 0x01}
	if ip4 := ip.To4(); ip4 != nil {
		rep = append(rep, ip4...)
	} else {
		rep[3] = 0x04
		rep = append(rep, ip.To16()...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	rep = append(rep, pb...)
	_, err := c.Write(rep)
	return err
}
