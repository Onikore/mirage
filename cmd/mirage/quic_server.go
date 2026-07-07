package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"mirage/internal/protocol"
	"mirage/internal/socks"
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

	_, consumed, err := protocol.ServerHandshake(mquic.NewStreamConn(qc, stream0), privs.Load(), ps.Load(), rc, func() (net.Conn, error) {
		return net.DialTimeout("tcp", dest, 5*time.Second)
	})
	if err != nil {
		// Для QUIC fallback сложнее (нельзя просто передать TCP-соединение),
		// но мы можем проксировать сырые данные через новый TCP-коннект к dest.
		// Пока что мы просто закроем QUIC-соединение для невалидных клиентов.
		_ = consumed // в TCP это отправлялось в dest
		qc.CloseWithError(1, "auth failed")
		return
	}

	// Хендшейк прошёл успешно на stream0. 
	// Запускаем обработчик UDP-датаграмм
	go serveQUICDatagrams(qc)

	// Теперь принимаем новые QUIC-стримы, в каждом из которых клиент шлёт SOCKS5-запрос.
	for {
		st, err := qc.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go serveQUICStream(st, dest)
	}
}

func serveQUICStream(st *quic.Stream, dest string) {
	target, err := socks.ReadAddr(st)
	if err != nil {
		st.Close()
		return
	}
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("quic dial %s: %v", target, err)
		st.Close()
		return
	}
	log.Printf("quic tunnel -> %s", target)
	relay(st, remote)
}

type udpClient struct {
	conn       *net.UDPConn
	lastActive time.Time
}

func serveQUICDatagrams(qc *quic.Conn) {
	var mu sync.Mutex
	clients := make(map[uint32]*udpClient)

	go func() {
		for {
			select {
			case <-time.After(1 * time.Minute):
				mu.Lock()
				now := time.Now()
				for id, c := range clients {
					if now.Sub(c.lastActive) > 2*time.Minute {
						c.conn.Close()
						delete(clients, id)
					}
				}
				mu.Unlock()
			case <-qc.Context().Done():
				mu.Lock()
				for _, c := range clients {
					c.conn.Close()
				}
				mu.Unlock()
				return
			}
		}
	}()

	for {
		b, err := qc.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(b) < 4 {
			continue
		}
		id := binary.BigEndian.Uint32(b[:4])
		data := b[4:]

		if len(data) < 4 {
			continue
		}
		var targetHost string
		var targetPort uint16
		var headerLen int

		switch data[3] {
		case 0x01:
			if len(data) < 10 {
				continue
			}
			targetHost = net.IP(data[4:8]).String()
			targetPort = binary.BigEndian.Uint16(data[8:10])
			headerLen = 10
		case 0x04:
			if len(data) < 22 {
				continue
			}
			targetHost = net.IP(data[4:20]).String()
			targetPort = binary.BigEndian.Uint16(data[20:22])
			headerLen = 22
		case 0x03:
			if len(data) < 5 {
				continue
			}
			l := int(data[4])
			if len(data) < 5+l+2 {
				continue
			}
			targetHost = string(data[5 : 5+l])
			targetPort = binary.BigEndian.Uint16(data[5+l : 5+l+2])
			headerLen = 5 + l + 2
		default:
			continue
		}

		targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
		uaddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			continue
		}

		mu.Lock()
		c, ok := clients[id]
		if !ok {
			conn, err := net.ListenUDP("udp", nil)
			if err == nil {
				c = &udpClient{conn: conn, lastActive: time.Now()}
				clients[id] = c
				go func(clientID uint32, udpConn *net.UDPConn) {
					buf := make([]byte, 2048)
					for {
						n, raddr, err := udpConn.ReadFromUDP(buf)
						if err != nil {
							return
						}
						head := []byte{0, 0, 0}
						if ip4 := raddr.IP.To4(); ip4 != nil {
							head = append(head, 0x01)
							head = append(head, ip4...)
						} else {
							head = append(head, 0x04)
							head = append(head, raddr.IP.To16()...)
						}
						pb := make([]byte, 2)
						binary.BigEndian.PutUint16(pb, uint16(raddr.Port))
						head = append(head, pb...)

						out := make([]byte, 4+len(head)+n)
						binary.BigEndian.PutUint32(out, clientID)
						copy(out[4:], head)
						copy(out[4+len(head):], buf[:n])
						qc.SendDatagram(out)

						mu.Lock()
						if cl, ok := clients[clientID]; ok {
							cl.lastActive = time.Now()
						}
						mu.Unlock()
					}
				}(id, conn)
			}
		}
		if c != nil {
			c.lastActive = time.Now()
		}
		mu.Unlock()

		if c != nil {
			c.conn.WriteToUDP(data[headerLen:], uaddr)
		}
	}
}
