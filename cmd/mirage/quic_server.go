package main

// quic_server.go -- принимает QUIC-соединения. Как и quic_client.go, stream0
// (где проходит рукопожатие) становится единственным носителем всей сессии
// через protocol.NewSession -- реальный проксируемый трафик защищён
// Noise-сессией, а не только (самоподписанным, непроверяемым клиентом)
// TLS самого QUIC. SOCKS5 UDP ASSOCIATE через QUIC не поддерживается (как и
// в TCP-режиме) -- см. clientConn в main.go.

import (
	"context"
	"net"
	"time"

	"mirage/internal/protocol"
	mquic "mirage/internal/transport/quic"

	"github.com/quic-go/quic-go"
)

func serveQUICConn(qc *quic.Conn, privs *privSet, ps *pskSet, dest string, rc *protocol.ReplayCache, il *ipLimiter) {
	host, _, err := net.SplitHostPort(qc.RemoteAddr().String())
	if err != nil {
		host = qc.RemoteAddr().String()
	}
	if !il.allow(host) {
		qc.CloseWithError(1, "rate limited")
		return
	}

	stream0, err := qc.AcceptStream(context.Background())
	if err != nil {
		qc.CloseWithError(1, "stream error")
		return
	}

	sc, consumed, err := protocol.ServerHandshake(mquic.NewStreamConn(qc, stream0), privs.Load(), ps.Load(), rc, func() (net.Conn, error) {
		return net.DialTimeout("tcp", dest, 5*time.Second)
	})
	if err != nil {
		// Для QUIC fallback сложнее (нельзя просто передать TCP-соединение
		// пробера в fallback-проброс) -- пока просто закрываем QUIC-соединение
		// для невалидных клиентов.
		_ = consumed
		qc.CloseWithError(1, "auth failed")
		return
	}

	sess := protocol.NewSession(sc)
	for {
		st, payload, err := sess.Accept()
		if err != nil {
			return // сессия закрыта (клиент отключился) -- нормальное завершение
		}
		go serveStream(st, payload, dest)
	}
}
