package main

// addr.go — кодирование целевого адреса (как в SOCKS5).
// Клиент шлёт это первым сообщением после рукопожатия; сервер туда дозванивается.
//   [atyp u8][addr][port u16 BE]
//   atyp: 1=IPv4(4B) 3=domain(len u8 + bytes) 4=IPv6(16B)

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

func encodeAddr(host string, port uint16) []byte {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append([]byte{1}, ip4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		b = append([]byte{3, byte(len(host))}, []byte(host)...)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	return append(b, p...)
}

func readAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 1:
		var v4 [4]byte
		if _, err := io.ReadFull(r, v4[:]); err != nil {
			return "", err
		}
		host = net.IP(v4[:]).String()
	case 4:
		var v6 [16]byte
		if _, err := io.ReadFull(r, v6[:]); err != nil {
			return "", err
		}
		host = net.IP(v6[:]).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", errors.New("mirage: bad atyp")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(p[:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
