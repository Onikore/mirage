package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func generateDummyTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Mirage"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"mirage-quic"},
	}
}

// Server wrapper
type Server struct {
	listener *quic.Listener
}

func Listen(addr string, getPSKs func() [][]byte) (*Server, error) {
	tlsConf := generateDummyTLSConfig()
	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		EnableDatagrams: true,
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	var packetConn net.PacketConn = conn
	if getPSKs != nil {
		packetConn = NewObfuscatedPacketConn(conn, getPSKs)
	}
	listener, err := quic.Listen(packetConn, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	return &Server{listener: listener}, nil
}

func (s *Server) Accept(ctx context.Context) (*quic.Conn, error) {
	return s.listener.Accept(ctx)
}

func (s *Server) Close() error {
	return s.listener.Close()
}

// Client wrapper
func Dial(addr string, getPSKs func() [][]byte) (*quic.Conn, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"mirage-quic"},
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		EnableDatagrams: true,
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	var packetConn net.PacketConn = conn
	if getPSKs != nil {
		packetConn = NewObfuscatedPacketConn(conn, getPSKs)
	}
	return quic.Dial(context.Background(), packetConn, udpAddr, tlsConf, quicConf)
}

// StreamConn wraps a quic.Stream to implement net.Conn
type StreamConn struct {
	*quic.Stream
	qc *quic.Conn
}

func NewStreamConn(qc *quic.Conn, stream *quic.Stream) *StreamConn {
	return &StreamConn{Stream: stream, qc: qc}
}

func (s *StreamConn) LocalAddr() net.Addr {
	return s.qc.LocalAddr()
}

func (s *StreamConn) RemoteAddr() net.Addr {
	return s.qc.RemoteAddr()
}
