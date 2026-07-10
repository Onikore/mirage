package main

// quic_client.go -- dials a mirage server over QUIC instead of TCP. Unlike
// the vulnerable version this replaces, it does NOT discard the Noise
// handshake's result: stream0 (where the handshake runs) becomes the single
// carrier for the whole mirage session via protocol.NewSession, exactly like
// TCP mode -- so real proxied traffic is protected by the Noise session, not
// merely by QUIC's own unauthenticated TLS (self-signed cert on the server,
// InsecureSkipVerify on the client -- see internal/transport/quic/quic.go).
// This means SOCKS5 UDP ASSOCIATE is not supported over QUIC either, same as
// TCP (see tcpSession) -- see clientConn in main.go for the clean rejection.

import (
	"context"
	"fmt"

	"mirage/internal/protocol"
	mquic "mirage/internal/transport/quic"
)

func dialSessionQUIC(server string, pub, psk []byte, sni string) (ClientSession, error) {
	getPSKs := func() [][]byte { return [][]byte{psk} }
	qc, err := mquic.Dial(server, getPSKs)
	if err != nil {
		return nil, fmt.Errorf("dial quic: %w", err)
	}

	stream0, err := qc.OpenStreamSync(context.Background())
	if err != nil {
		qc.CloseWithError(1, "")
		return nil, fmt.Errorf("open stream0: %w", err)
	}

	sc, err := protocol.ClientHandshake(mquic.NewStreamConn(qc, stream0), pub, psk, sni)
	if err != nil {
		qc.CloseWithError(1, "")
		return nil, fmt.Errorf("quic handshake: %w", err)
	}

	return tcpSession{protocol.NewSession(sc)}, nil
}
