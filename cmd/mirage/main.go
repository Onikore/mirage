package main

// main.go — подкоманды: keygen | server | client | gui
//
//   mirage keygen
//   mirage server -listen :8443 -priv <hex> -psk <hex> -dest example.com:443
//   mirage client -listen 127.0.0.1:1080 -server HOST:8443 -pub <hex> -psk <hex>
//   mirage gui   (только Windows-сборка — см. gui_windows.go)
//
// Клиент делает одно рукопожатие на процесс (не на запрос) и мультиплексирует
// все SOCKS5-запросы по одной сессии — см. internal/protocol/mux.go.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/flynn/noise"

	"mirage/internal/protocol"
	"mirage/internal/socks"
	mquic "mirage/internal/transport/quic"
)

func main() {
	if isPluginMode() {
		runPluginMode()
		return
	}

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
	privHex := fs.String("priv", "", "server private key (hex), single-key mode")
	privFile := fs.String("priv-file", "", "file with one hex priv key per line; supports multiple simultaneously-valid keys and SIGHUP reload")
	pskHex := fs.String("psk", "", "pre-shared key (hex), single-key mode")
	pskFile := fs.String("psk-file", "", "file with one hex psk per line; supports multiple simultaneously-valid keys and SIGHUP reload (for zero-downtime rotation)")
	dest := fs.String("dest", "example.com:443", "fallback destination for probers")
	padding := fs.Bool("padding", false, "add periodic random-size padding frames to obscure session timing/size patterns (generic obfuscation, not a precise protocol-profile match)")
	quicMode := fs.Bool("quic", false, "use QUIC transport instead of TCP")
	apiAddr := fs.String("api", "", "HTTP API address for stats (e.g. 127.0.0.1:8080)")
	fs.Parse(args)

	if *apiAddr != "" {
		go runStatsServer(*apiAddr)
	}

	privs := newPrivSet(loadInitialPrivs(*privHex, *privFile))
	ps := newPSKSet(loadInitialPSKs(*pskHex, *pskFile))
	if *pskFile != "" || *privFile != "" {
		watchKeyFilesReload(*pskFile, *pskHex, ps, *privFile, *privHex, privs)
	}
	rc := protocol.NewReplayCache(protocol.ReplayWindow)
	il := newIPLimiter()

	if *quicMode {
		log.Printf("server listening on %s (QUIC mode, fallback -> %s)", *listen, *dest)
		qs, err := mquic.Listen(*listen, ps.Load)
		if err != nil {
			log.Fatal(err)
		}
		for {
			qc, err := qs.Accept(context.Background())
			if err != nil {
				continue
			}
			go serveQUICConn(qc, privs, ps, *dest, rc, il)
		}
	} else {
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("server listening on %s (TCP mode, fallback -> %s)", *listen, *dest)
		for {
			c, err := ln.Accept()
			if err != nil {
				continue
			}
			go serveConn(c, privs, ps, *dest, rc, il, *padding)
		}
	}
}

// loadInitialPrivs объединяет -priv и -priv-file
func loadInitialPrivs(privHex, privFile string) []noise.DHKey {
	var keys []noise.DHKey
	if privHex != "" {
		dh, err := protocol.DHKeyFromPriv(mustHex(privHex))
		if err != nil {
			log.Fatal("bad priv: ", err)
		}
		keys = append(keys, dh)
	}
	if privFile != "" {
		fileKeys, err := loadPrivFile(privFile)
		if err != nil {
			log.Fatal("priv-file: ", err)
		}
		keys = append(keys, fileKeys...)
	}
	if len(keys) == 0 {
		log.Fatal("no priv configured: pass -priv and/or -priv-file")
	}
	return keys
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

// watchKeyFilesReload перечитывает pskFile и privFile по SIGHUP и атомарно подменяет
// наборы.
func watchKeyFilesReload(pskFile, pskHex string, ps *pskSet, privFile, privHex string, privs *privSet) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	go func() {
		for range sigs {
			if pskFile != "" {
				fileKeys, err := loadPSKFile(pskFile)
				if err != nil {
					log.Printf("psk-file reload failed, keeping current set: %v", err)
				} else {
					var next [][]byte
					if pskHex != "" {
						next = append(next, mustHex(pskHex))
					}
					next = append(next, fileKeys...)
					ps.Store(next)
					log.Printf("psk-file reloaded: %d key(s) active", len(next))
				}
			}
			if privFile != "" {
				fileKeys, err := loadPrivFile(privFile)
				if err != nil {
					log.Printf("priv-file reload failed, keeping current set: %v", err)
				} else {
					var next []noise.DHKey
					if privHex != "" {
						dh, _ := protocol.DHKeyFromPriv(mustHex(privHex))
						next = append(next, dh)
					}
					next = append(next, fileKeys...)
					privs.Store(next)
					log.Printf("priv-file reloaded: %d key(s) active", len(next))
				}
			}
		}
	}()
}

func serveConn(c net.Conn, privs *privSet, ps *pskSet, dest string, rc *protocol.ReplayCache, il *ipLimiter, padding bool) {
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

	sc, consumed, err := protocol.ServerHandshake(c, privs.Load(), ps.Load(), rc, func() (net.Conn, error) {
		return net.DialTimeout("tcp", dest, 5*time.Second)
	})
	if err != nil {
		// зонд/мусор -> прозрачный проброс на реальный сайт, переигрывая прочитанное
		atomic.AddUint64(&statProbesRejected, 1)
		log.Printf("probe -> transparent proxy to %s (err: %v)", dest, err)
		fallback(c, consumed, dest)
		return
	}

	atomic.AddInt64(&statActiveConns, 1)
	defer atomic.AddInt64(&statActiveConns, -1)
	c.SetDeadline(time.Time{}) // снять дедлайн для установленной сессии

	sess := protocol.NewSession(sc)
	if padding {
		sess.StartPadding(1*time.Second, 5*time.Second, 32, 256)
	}
	for {
		st, payload, err := sess.Accept()
		if err != nil {
			return // сессия закрыта (клиент отключился) -- нормальное завершение
		}
		go serveStream(st, payload, dest)
	}
}

// serveStream дозванивается до цели, закодированной в OPEN-payload стрима,
// и сшивает поток с ней. Одна горутина на стрим -- несколько запросов через
// одну и ту же сессию обслуживаются параллельно.
func serveStream(st *protocol.Stream, payload []byte, dest string) {
	var target string
	if pluginTarget != "" {
		// В режиме серверного плагина весь расшифрованный трафик отправляется
		// на SS_LOCAL_HOST:SS_LOCAL_PORT (т.е. на сам SS-сервер).
		target = pluginTarget
	} else {
		var err error
		target, err = socks.ReadAddr(bytes.NewReader(payload))
		if err != nil {
			st.Close()
			return
		}
	}

	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		st.Close()
		return
	}
	log.Printf("tunnel -> %s", target)
	relayStats(st, remote)
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
	padding := fs.Bool("padding", false, "add periodic random-size padding frames to obscure session timing/size patterns (generic obfuscation, not a precise protocol-profile match)")
	fragment := fs.Bool("fragment", false, "fragment the initial ClientHello to bypass DPI")
	quicMode := fs.Bool("quic", false, "use QUIC transport instead of TCP")
	fs.Parse(args)

	pub := mustHex(*pubHex)
	psk := mustHex(*pskHex)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}

	dial := func() (ClientSession, error) {
		if *quicMode {
			return dialSessionQUIC(*server, pub, psk, *sni)
		}
		return dialSessionTCP(*server, pub, psk, *sni, *padding, *fragment)
	}

	// Первый коннект остаётся fail-fast -- если сервер недоступен или
	// рукопожатие не проходит уже при старте, процесс завершается сразу, а
	// не поднимает SOCKS5 вслепую (см. design spec, Global Constraints).
	sess, err := dial()
	if err != nil {
		log.Fatal(err)
	}

	h := newSessionHolder(sess, dial, func(s string) { log.Print(s) }, time.Second, 30*time.Second)

	log.Printf("SOCKS5 on %s -> mirage %s (session established)", *listen, *server)
	runClientListener(ln, h)
}

// runClientListener принимает соединения на ln и обслуживает их до тех пор,
// пока ln не закроют (например, вызовом ln.Close() из другой горутины —
// так GUI-клиент реализует «Disconnect»). Все локальные SOCKS5-запросы
// открывают новый Stream на текущей сессии holder'а h — если сессия прямо
// сейчас недоступна (идёт автопереподключение), запрос сразу отклоняется
// (см. clientConn).
func runClientListener(ln net.Listener, h *sessionHolder) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go clientConn(c, h)
	}
}

func clientConn(c net.Conn, h *sessionHolder) {
	defer c.Close()

	if pluginTarget == "transparent" {
		sess := h.Current()
		if sess == nil {
			return
		}
		// Send an empty address or a dummy address because the SS Server handles targeting.
		st, err := sess.Open([]byte{0}) // Minimal dummy payload
		if err != nil {
			log.Printf("open stream: %v", err)
			return
		}
		relayStats(st, c)
		return
	}

	cmd, host, port, err := socks.Accept(c)
	if err != nil {
		log.Printf("socks accept: %v", err)
		return
	}

	sess := h.Current()
	if sess == nil {
		return
	}

	if cmd != 0x01 { // only CONNECT is supported
		// UDP ASSOCIATE (0x03) is rejected cleanly rather than accepted and
		// silently dropping every datagram: relaying UDP over the tunnel would
		// need its own encrypted, loss-tolerant framing (github.com/flynn/noise's
		// CipherState.Decrypt requires strictly-ordered, no-missing-messages
		// delivery, which real UDP can't guarantee), and that hasn't been
		// designed/reviewed yet.
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	socks.SendSuccessReply(c, net.IPv4zero, 0)
	st, err := sess.Open(socks.EncodeAddr(host, port))
	if err != nil {
		log.Printf("open stream: %v", err)
		return
	}
	relayStats(st, c)
}
