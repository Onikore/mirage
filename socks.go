package main

// socks.go — минимальный SOCKS5 (no-auth, только CONNECT) как локальный вход клиента.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

// socksAccept разбирает SOCKS5 CONNECT и возвращает host, port.
func socksAccept(c net.Conn) (string, uint16, error) {
	// greeting: ver, nmethods, methods...
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", 0, err
	}
	if head[0] != 0x05 {
		return "", 0, errors.New("socks: not v5")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", 0, err
	}
	// no-auth
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, err
	}

	// request: ver cmd rsv atyp ...
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", 0, err
	}
	if req[1] != 0x01 { // CONNECT
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", 0, errors.New("socks: only CONNECT")
	}

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
		return "", 0, errors.New("socks: bad atyp")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(pb)

	// success reply (bind addr фиктивный)
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	_ = strconv.Itoa
	return host, port, nil
}
