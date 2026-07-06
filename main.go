package main

// main.go — подкоманды: keygen | server | client
//
//   mirage keygen
//   mirage server -listen :8443 -priv <hex> -psk <hex> -dest example.com:443
//   mirage client -listen 127.0.0.1:1080 -server HOST:8443 -pub <hex> -psk <hex>
//
// Скелет: одно tunnel-соединение на один SOCKS5-запрос (mux — TODO).

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: mirage <keygen|server|client> [flags]")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen()
	case "server":
		cmdServer(os.Args[2:])
	case "client":
		cmdClient(os.Args[2:])
	default:
		fmt.Println("unknown subcommand:", os.Args[1])
		os.Exit(1)
	}
}

func cmdKeygen() {
	priv, err := genKey()
	if err != nil {
		log.Fatal(err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)
	fmt.Println("server_priv:", hex.EncodeToString(priv.Bytes()))
	fmt.Println("server_pub: ", hex.EncodeToString(priv.PublicKey().Bytes()))
	fmt.Println("psk:        ", hex.EncodeToString(psk))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// relay двунаправленно копирует и закрывает оба конца.
func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
}

// ---------------- server ----------------

func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "listen address")
	privHex := fs.String("priv", "", "server private key (hex)")
	pskHex := fs.String("psk", "", "pre-shared key (hex)")
	dest := fs.String("dest", "example.com:443", "fallback destination for probers")
	fs.Parse(args)

	priv, err := curve.NewPrivateKey(mustHex(*privHex))
	if err != nil {
		log.Fatal("bad priv: ", err)
	}
	psk := mustHex(*pskHex)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("server listening on %s (fallback -> %s)", *listen, *dest)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go serveConn(c, priv, psk, *dest)
	}
}

func serveConn(c net.Conn, priv *ecdh.PrivateKey, psk []byte, dest string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	sc, consumed, err := serverHandshake(c, priv, psk)
	if err != nil {
		// зонд/мусор -> прозрачный проброс на реальный сайт, переигрывая прочитанное
		fallback(c, consumed, dest)
		return
	}
	c.SetDeadline(time.Time{}) // снять дедлайн для установленной сессии

	target, err := readAddr(sc)
	if err != nil {
		return
	}
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	log.Printf("tunnel -> %s", target)
	relay(sc, remote)
}

// fallback выдаёт зонду настоящий сайт: реиграет уже прочитанные байты и сшивает потоки.
func fallback(client net.Conn, consumed []byte, dest string) {
	up, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		client.Close()
		return
	}
	client.SetDeadline(time.Time{})
	if len(consumed) > 0 {
		up.Write(consumed)
	}
	log.Printf("probe -> transparent proxy to %s", dest)
	relay(client, up)
}

// ---------------- client ----------------

func cmdClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listen")
	server := fs.String("server", "", "mirage server HOST:PORT")
	pubHex := fs.String("pub", "", "server public key (hex)")
	pskHex := fs.String("psk", "", "pre-shared key (hex)")
	sni := fs.String("sni", "www.google.com", "SNI hostname to wear in the disguised ClientHello")
	fs.Parse(args)

	pub := mustHex(*pubHex)
	psk := mustHex(*pskHex)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 on %s -> mirage %s", *listen, *server)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go clientConn(c, *server, pub, psk, *sni)
	}
}

func clientConn(c net.Conn, server string, pub, psk []byte, sni string) {
	defer c.Close()
	host, port, err := socksAccept(c)
	if err != nil {
		return
	}

	up, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		log.Printf("dial server: %v", err)
		return
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	sc, err := clientHandshake(up, pub, psk, sni)
	if err != nil {
		log.Printf("handshake: %v", err)
		up.Close()
		return
	}
	up.SetDeadline(time.Time{})

	// первый фрейм — целевой адрес
	if _, err := sc.Write(encodeAddr(host, port)); err != nil {
		sc.Close()
		return
	}
	relay(sc, c)
}
