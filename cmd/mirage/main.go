package main

// main.go — подкоманды: keygen | server | client | gui
//
//   mirage keygen
//   mirage server -listen :8443 -priv <hex> -psk <hex> -dest example.com:443
//   mirage client -listen 127.0.0.1:1080 -server HOST:8443 -pub <hex> -psk <hex>
//   mirage gui   (только Windows-сборка — см. gui_windows.go)
//
// Скелет: одно tunnel-соединение на один SOCKS5-запрос (mux — TODO).

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flynn/noise"

	"mirage/internal/protocol"
	"mirage/internal/socks"
)

func main() {
	// Без аргументов — сразу GUI: двойной клик по mirage-gui.exe из
	// Проводника запускает процесс без аргументов, а у windowsgui-подсистемы
	// нет консоли, чтобы показать usage — значит, ничего лучше не остаётся.
	if len(os.Args) < 2 {
		cmdGUI()
		return
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen()
	case "server":
		cmdServer(os.Args[2:])
	case "client":
		cmdClient(os.Args[2:])
	case "gui":
		cmdGUI()
	default:
		fmt.Println("unknown subcommand:", os.Args[1])
		os.Exit(1)
	}
}

func cmdKeygen() {
	kp, err := protocol.GenKeypair()
	if err != nil {
		log.Fatal(err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)
	fmt.Println("server_priv:", hex.EncodeToString(kp.Private))
	fmt.Println("server_pub: ", hex.EncodeToString(kp.Public))
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
	pskHex := fs.String("psk", "", "pre-shared key (hex), single-key mode")
	pskFile := fs.String("psk-file", "", "file with one hex psk per line; supports multiple simultaneously-valid keys and SIGHUP reload (for zero-downtime rotation)")
	dest := fs.String("dest", "example.com:443", "fallback destination for probers")
	fs.Parse(args)

	priv, err := protocol.DHKeyFromPriv(mustHex(*privHex))
	if err != nil {
		log.Fatal("bad priv: ", err)
	}
	ps := newPSKSet(loadInitialPSKs(*pskHex, *pskFile))
	if *pskFile != "" {
		watchPSKFileReload(*pskFile, *pskHex, ps)
	}
	rc := protocol.NewReplayCache(protocol.ReplayWindow)
	il := newIPLimiter()

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
		go serveConn(c, priv, ps, *dest, rc, il)
	}
}

// loadInitialPSKs объединяет -psk (если задан) и -psk-file (если задан) в
// один начальный набор. Пусто в обоих — фатальная ошибка конфигурации: явный
// отказ при старте лучше, чем сервер, который потом молча отвергает всех.
func loadInitialPSKs(pskHex, pskFile string) [][]byte {
	var keys [][]byte
	if pskHex != "" {
		keys = append(keys, mustHex(pskHex))
	}
	if pskFile != "" {
		fileKeys, err := loadPSKFile(pskFile)
		if err != nil {
			log.Fatal("psk-file: ", err)
		}
		keys = append(keys, fileKeys...)
	}
	if len(keys) == 0 {
		log.Fatal("no psk configured: pass -psk and/or -psk-file")
	}
	return keys
}

// watchPSKFileReload перечитывает pskFile по SIGHUP и атомарно подменяет
// набор в ps — старые соединения не рвутся, новые попытки видят
// обновлённый список. -psk (если был задан) остаётся действующим при
// каждой перезагрузке. Плохой файл при перезагрузке — старый набор
// сохраняется, ошибка только логируется (не блокировать всех опечаткой).
func watchPSKFileReload(pskFile, pskHex string, ps *pskSet) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	go func() {
		for range sigs {
			fileKeys, err := loadPSKFile(pskFile)
			if err != nil {
				log.Printf("psk-file reload failed, keeping current set: %v", err)
				continue
			}
			var next [][]byte
			if pskHex != "" {
				next = append(next, mustHex(pskHex))
			}
			next = append(next, fileKeys...)
			ps.Store(next)
			log.Printf("psk-file reloaded: %d key(s) active", len(next))
		}
	}()
}

func serveConn(c net.Conn, priv noise.DHKey, ps *pskSet, dest string, rc *protocol.ReplayCache, il *ipLimiter) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		host = c.RemoteAddr().String()
	}
	if !il.allow(host) {
		// превышен лимит попыток с этого IP -> прямиком в fallback, без крипто-работы
		fallback(c, nil, dest)
		return
	}

	sc, consumed, err := protocol.ServerHandshake(c, priv, ps.Load(), rc)
	if err != nil {
		// зонд/мусор -> прозрачный проброс на реальный сайт, переигрывая прочитанное
		fallback(c, consumed, dest)
		return
	}
	c.SetDeadline(time.Time{}) // снять дедлайн для установленной сессии

	target, err := socks.ReadAddr(sc)
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
	runClientListener(ln, *server, pub, psk, *sni)
}

// runClientListener принимает соединения на ln и обслуживает их до тех пор,
// пока ln не закроют (например, вызовом ln.Close() из другой горутины —
// так GUI-клиент реализует «Disconnect»). Возврат из Accept с ошибкой
// трактуется как «слушатель закрыт, пора остановиться», а не как повод
// молотить цикл дальше.
func runClientListener(ln net.Listener, server string, pub, psk []byte, sni string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go clientConn(c, server, pub, psk, sni)
	}
}

func clientConn(c net.Conn, server string, pub, psk []byte, sni string) {
	defer c.Close()
	host, port, err := socks.Accept(c)
	if err != nil {
		return
	}

	up, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		log.Printf("dial server: %v", err)
		return
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	sc, err := protocol.ClientHandshake(up, pub, psk, sni)
	if err != nil {
		log.Printf("handshake: %v", err)
		up.Close()
		return
	}
	up.SetDeadline(time.Time{})

	// первый фрейм — целевой адрес
	if _, err := sc.Write(socks.EncodeAddr(host, port)); err != nil {
		sc.Close()
		return
	}
	relay(sc, c)
}
