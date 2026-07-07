package main

import (
	"context"
	"fmt"
	"io"

	"mirage/internal/protocol"
	mquic "mirage/internal/transport/quic"

	"github.com/quic-go/quic-go"
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
	// We don't use sc after handshake because QUIC TLS provides encryption.
	// We can leave stream0 open or close it.
	_ = sc

	return &quicSession{
		qc: qc,
	}, nil
}

type quicSession struct {
	qc *quic.Conn
}

func (q *quicSession) Done() <-chan struct{} {
	return q.qc.Context().Done()
}

func (q *quicSession) Err() error {
	return q.qc.Context().Err()
}

func (q *quicSession) Close() error {
	return q.qc.CloseWithError(0, "")
}

func (q *quicSession) Open(payload []byte) (io.ReadWriteCloser, error) {
	st, err := q.qc.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	if len(payload) > 0 {
		if _, err := st.Write(payload); err != nil {
			st.Close()
			return nil, err
		}
	}
	return st, nil
}

func (q *quicSession) SendDatagram(payload []byte) error {
	return q.qc.SendDatagram(payload)
}

func (q *quicSession) ReceiveDatagram() ([]byte, error) {
	return q.qc.ReceiveDatagram(context.Background())
}
