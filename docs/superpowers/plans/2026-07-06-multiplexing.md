# Session Multiplexing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Multiplex many logical request streams over one Noise-authenticated
TCP session, instead of one handshake per SOCKS5 request.

**Architecture:** New `Session`/`Stream` layer in `internal/protocol/mux.go`
sits on top of the existing `*SecureConn` (unchanged) via a tiny
length-prefixed frame protocol. `cmd/mirage/main.go` is rewired: the client
establishes one `Session` per process and opens a `Stream` per SOCKS5
request instead of dialing+handshaking every time; the server keeps its
existing one-handshake-per-TCP-connection flow (rate-limit/anti-replay checks
are unaffected — they gate the handshake, not what happens after it) but then
loops accepting streams from the resulting `Session` instead of a single
`readAddr`+`relay`.

**Tech Stack:** Go stdlib only for this package (`encoding/binary`, `sync`,
`sync/atomic`, `io`) — no new external dependency.

## Global Constraints

- `internal/protocol/frame.go` (`SecureConn`) is NOT modified — `Session`
  wraps it purely via the `io.ReadWriteCloser` interface it already
  satisfies.
- Frame wire format inside the decrypted stream: `[u32 streamID][u8
  type][u16 len][payload]`. Frame types: `1`=OPEN, `2`=DATA, `3`=CLOSE.
- `mux.go` must NOT know about address encoding — `Open`/`Accept` deal in
  raw `[]byte` payloads. The caller (`cmd/mirage/main.go`) is responsible
  for encoding/decoding the OPEN payload via the existing
  `socks.EncodeAddr`/`socks.ReadAddr`.
- Exactly one writer goroutine touches `conn.Write` at a time (serialized via
  a mutex) and exactly one reader goroutine (the `readLoop`) calls
  `conn.Read` — this matches `net.Conn`'s documented concurrency contract
  (one concurrent reader + one concurrent writer is safe without extra
  locking at the `SecureConn` level).
- Rate-limiting (`ratelimit.go`) and the anti-replay cache (`replay.go`) are
  NOT touched — they already gate the one-handshake-per-TCP-connection
  point, which does not change.
- No auto-reconnect if the underlying session dies — out of scope, matches
  the project's existing "not battle-tested" posture (document as a known
  limitation, not silently).

---

### Task 1: `internal/protocol/mux.go` — Session/Stream core

**Files:**
- Create: `internal/protocol/mux.go`
- Test: `internal/protocol/mux_test.go`

**Interfaces:**
- Produces (consumed by Task 2):
  - `func NewSession(conn io.ReadWriteCloser) *Session`
  - `func (s *Session) Open(payload []byte) (*Stream, error)` (client side)
  - `func (s *Session) Accept() (*Stream, []byte, error)` (server side;
    second return is the OPEN frame's payload)
  - `type Stream struct{...}` implementing `Read([]byte) (int, error)`,
    `Write([]byte) (int, error)`, `Close() error` (i.e. `io.ReadWriteCloser`)

This design was hand-verified in a throwaway prototype (net.Pipe, 5
concurrent streams, close-propagation, clean under `-race`) before writing
this plan — the code below is that verified design, transcribed for this
package. Implement it exactly as given; do not redesign it.

- [ ] **Step 1: Write the file**

```go
package protocol

// mux.go — мультиплексирование логических стримов поверх одной сессии
// (одного *SecureConn). Формат кадра внутри уже расшифрованного потока:
//   [u32 streamID][u8 type][u16 len][payload]
// Один читатель (readLoop), запись сериализована мьютексом — это ровно
// контракт net.Conn (один параллельный читатель + один параллельный
// писатель), так что SecureConn не требует дополнительной синхронизации.
//
// ponytail: нет протокольного backpressure — при переполнении очереди
// принятых-но-невычитанных стримов новые OPEN тихо дропаются. Апгрейд —
// добавить сигнал управления потоком, если станет проблемой.

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
)

const (
	frameOpen  byte = 1
	frameData  byte = 2
	frameClose byte = 3
)

// Session мультиплексирует много Stream поверх одного io.ReadWriteCloser
// (в проекте — *SecureConn).
type Session struct {
	conn     io.ReadWriteCloser
	wmu      sync.Mutex
	mu       sync.Mutex
	streams  map[uint32]*Stream
	nextID   uint32
	acceptCh chan *Stream
	closed   chan struct{}
	closeErr error
}

func NewSession(conn io.ReadWriteCloser) *Session {
	s := &Session{
		conn:     conn,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, 16),
		closed:   make(chan struct{}),
	}
	go s.readLoop()
	return s
}

func (s *Session) writeFrame(id uint32, typ byte, payload []byte) error {
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint32(hdr[0:4], id)
	hdr[4] = typ
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))

	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) readLoop() {
	defer s.shutdown(io.EOF)
	hdr := make([]byte, 7)
	for {
		if _, err := io.ReadFull(s.conn, hdr); err != nil {
			s.shutdown(err)
			return
		}
		id := binary.BigEndian.Uint32(hdr[0:4])
		typ := hdr[4]
		n := binary.BigEndian.Uint16(hdr[5:7])
		payload := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.shutdown(err)
				return
			}
		}

		switch typ {
		case frameOpen:
			st := s.newStream(id)
			st.openPayload = payload
			select {
			case s.acceptCh <- st:
			default:
				// backlog full -- drop; см. doc-комментарий файла про backpressure
			}
		case frameData:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				select {
				case st.readCh <- payload:
				case <-st.closeCh:
				}
			}
		case frameClose:
			s.mu.Lock()
			st := s.streams[id]
			delete(s.streams, id)
			s.mu.Unlock()
			if st != nil {
				st.closeOnce.Do(func() { close(st.closeCh) })
			}
		}
	}
}

func (s *Session) newStream(id uint32) *Stream {
	st := &Stream{
		id:      id,
		session: s,
		readCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
	s.mu.Lock()
	s.streams[id] = st
	s.mu.Unlock()
	return st
}

// Open (клиентская сторона) открывает новый логический стрим; payload —
// содержимое OPEN-кадра (в проекте — закодированный адрес цели, см.
// socks.EncodeAddr).
func (s *Session) Open(payload []byte) (*Stream, error) {
	id := atomic.AddUint32(&s.nextID, 1)
	st := s.newStream(id)
	if err := s.writeFrame(id, frameOpen, payload); err != nil {
		return nil, err
	}
	return st, nil
}

// Accept (серверная сторона) блокируется до следующего открытого клиентом
// стрима и возвращает его вместе с OPEN-payload (адрес цели — декодирует
// вызывающий код через socks.ReadAddr).
func (s *Session) Accept() (*Stream, []byte, error) {
	select {
	case st := <-s.acceptCh:
		return st, st.openPayload, nil
	case <-s.closed:
		return nil, nil, s.closeErr
	}
}

func (s *Session) shutdown(err error) {
	s.mu.Lock()
	select {
	case <-s.closed:
		s.mu.Unlock()
		return
	default:
	}
	s.closeErr = err
	close(s.closed)
	for _, st := range s.streams {
		st.closeOnce.Do(func() { close(st.closeCh) })
	}
	s.mu.Unlock()
}

// Stream — один логический канал внутри Session; реализует
// io.ReadWriteCloser.
type Stream struct {
	id          uint32
	session     *Session
	openPayload []byte
	readCh      chan []byte
	readBuf     []byte
	closeCh     chan struct{}
	closeOnce   sync.Once
}

func (st *Stream) Write(p []byte) (int, error) {
	if err := st.session.writeFrame(st.id, frameData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (st *Stream) Read(p []byte) (int, error) {
	if len(st.readBuf) == 0 {
		select {
		case b, ok := <-st.readCh:
			if !ok {
				return 0, io.EOF
			}
			st.readBuf = b
		case <-st.closeCh:
			return 0, io.EOF
		}
	}
	n := copy(p, st.readBuf)
	st.readBuf = st.readBuf[n:]
	return n, nil
}

func (st *Stream) Close() error {
	st.session.mu.Lock()
	delete(st.session.streams, st.id)
	st.session.mu.Unlock()
	st.closeOnce.Do(func() { close(st.closeCh) })
	return st.session.writeFrame(st.id, frameClose, nil)
}
```

- [ ] **Step 2: Write the test file**

```go
package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
)

func TestSessionConcurrentStreams(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1)
	server := NewSession(c2)

	const nStreams = 5
	var wg sync.WaitGroup

	go func() {
		for i := 0; i < nStreams; i++ {
			st, payload, err := server.Accept()
			if err != nil {
				return
			}
			go func(st *Stream, payload []byte) {
				buf := make([]byte, 64)
				n, err := st.Read(buf)
				if err != nil {
					return
				}
				reply := append([]byte("echo("), payload...)
				reply = append(reply, []byte("):")...)
				reply = append(reply, buf[:n]...)
				st.Write(reply)
			}(st, payload)
		}
	}()

	results := make([][]byte, nStreams)
	for i := 0; i < nStreams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := []byte(fmt.Sprintf("target-%d", i))
			st, err := client.Open(target)
			if err != nil {
				t.Errorf("Open: %v", err)
				return
			}
			msg := []byte(fmt.Sprintf("hello-%d", i))
			if _, err := st.Write(msg); err != nil {
				t.Errorf("Write: %v", err)
				return
			}
			buf := make([]byte, 128)
			n, err := st.Read(buf)
			if err != nil {
				t.Errorf("Read: %v", err)
				return
			}
			results[i] = append([]byte(nil), buf[:n]...)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		want := []byte(fmt.Sprintf("echo(target-%d):hello-%d", i, i))
		if !bytes.Equal(r, want) {
			t.Errorf("stream %d: got %q want %q", i, r, want)
		}
	}
}

func TestStreamCloseYieldsEOF(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1)
	server := NewSession(c2)

	st, err := client.Open([]byte("x"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, _, err := server.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := st.Read(buf); err != io.EOF {
		t.Errorf("Read after close: err=%v, want io.EOF", err)
	}
}
```

- [ ] **Step 3: Run the tests**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go test ./internal/protocol/... -run 'TestSessionConcurrentStreams|TestStreamCloseYieldsEOF' -race -v
```

Expected: both PASS, no race warnings.

- [ ] **Step 4: Run the full protocol package suite to confirm nothing else broke**

```bash
go build ./... && go vet ./... && gofmt -l . && go test ./internal/protocol/... -race
```

Expected: clean build/vet/fmt, all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/mux.go internal/protocol/mux_test.go
git commit -m "feat: add Session/Stream multiplexing layer over SecureConn"
```

---

### Task 2: Wire multiplexing into `cmd/mirage/main.go`

**Files:**
- Modify: `cmd/mirage/main.go`

**Interfaces:**
- Consumes: `protocol.NewSession(conn io.ReadWriteCloser) *protocol.Session`,
  `(*protocol.Session) Open(payload []byte) (*protocol.Stream, error)`,
  `(*protocol.Session) Accept() (*protocol.Stream, []byte, error)` from Task 1.
  `*protocol.Stream` implements `io.ReadWriteCloser`.

This task requires judgment about control flow, not just transcription:
preserve the rate-limit/anti-replay/fallback behavior exactly as it is today
(they gate the handshake, which still happens exactly once per TCP
connection — nothing about them changes), and change ONLY what happens
after a successful handshake.

- [ ] **Step 1: Client side — one session per process, one stream per SOCKS5 request**

In `cmdClient`, after building `pub`/`psk`/`sni` and before the accept loop,
establish the upstream connection + handshake once:

```go
up, err := net.DialTimeout("tcp", *server, 10*time.Second)
if err != nil {
	log.Fatal("dial server: ", err)
}
up.SetDeadline(time.Now().Add(15 * time.Second))
sc, err := protocol.ClientHandshake(up, pub, psk, *sni)
if err != nil {
	log.Fatal("handshake: ", err)
}
up.SetDeadline(time.Time{})
sess := protocol.NewSession(sc)

log.Printf("SOCKS5 on %s -> mirage %s (session established)", *listen, *server)
runClientListener(ln, sess)
```

Change `runClientListener` and `clientConn` to take the shared `*protocol.Session`
instead of dialing/handshaking per connection:

```go
// runClientListener принимает соединения на ln и обслуживает их до тех пор,
// пока ln не закроют (например, вызовом ln.Close() из другой горутины —
// так GUI-клиент реализует «Disconnect»). Все локальные SOCKS5-запросы
// открывают новый Stream на ОДНОЙ и той же уже установленной sess — не
// дозваниваются и не проводят рукопожатие заново.
func runClientListener(ln net.Listener, sess *protocol.Session) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go clientConn(c, sess)
	}
}

func clientConn(c net.Conn, sess *protocol.Session) {
	defer c.Close()
	host, port, err := socks.Accept(c)
	if err != nil {
		return
	}

	st, err := sess.Open(socks.EncodeAddr(host, port))
	if err != nil {
		log.Printf("open stream: %v", err)
		return
	}
	relay(st, c)
}
```

Note `clientConn` no longer writes the addr as a first frame over the relay
— it's now the OPEN frame's payload, consumed by `Open`.

- [ ] **Step 2: Server side — accept-loop over the session, one relay goroutine per stream**

In `serveConn`, after a successful `protocol.ServerHandshake` (rate-limit and
fallback logic above it is UNCHANGED), replace the single
`socks.ReadAddr`+`relay` with a session accept loop:

```go
func serveConn(c net.Conn, priv noise.DHKey, ps *pskSet, dest string, rc *protocol.ReplayCache, il *ipLimiter) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		host = c.RemoteAddr().String()
	}
	if !il.allow(host) {
		fallback(c, nil, dest)
		return
	}

	sc, consumed, err := protocol.ServerHandshake(c, priv, ps.Load(), rc)
	if err != nil {
		fallback(c, consumed, dest)
		return
	}
	c.SetDeadline(time.Time{})

	sess := protocol.NewSession(sc)
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
	target, err := socks.ReadAddr(bytes.NewReader(payload))
	if err != nil {
		st.Close()
		return
	}
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		st.Close()
		return
	}
	log.Printf("tunnel -> %s", target)
	relay(st, remote)
}
```

Add `"bytes"` to `main.go`'s imports for `bytes.NewReader`.

- [ ] **Step 3: Remove now-unused code**

`fallback` and `relay` stay (still used). Confirm nothing else references
the old per-request dial/handshake pattern in `clientConn`.

- [ ] **Step 4: Build and test**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go build ./... && go vet ./... && gofmt -l . && go test ./... -race
```

Expected: clean build, no vet/fmt issues. Existing `cmd/mirage` tests
(`ratelimit_test.go`, `pskset_test.go`, `guiconfig_test.go`) still pass
unchanged — they don't touch `clientConn`/`serveConn`.
`runclient_test.go`'s `TestRunClientListenerReturnsWhenListenerClosed` calls
`runClientListener(ln, "127.0.0.1:1", nil, nil, "")` with the OLD signature —
update it to build a session-based call instead:

```go
func TestRunClientListenerReturnsWhenListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c1, _ := net.Pipe()
	sess := protocol.NewSession(c1)

	done := make(chan struct{})
	go func() {
		runClientListener(ln, sess)
		close(done)
	}()

	ln.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runClientListener did not return after listener was closed")
	}
}
```

(Add `"mirage/internal/protocol"` and drop the now-unused args from the old
call in this test file.)

- [ ] **Step 5: Windows cross-compile check**

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./... 2>&1
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/mirage-mux-test.exe ./cmd/mirage
file /tmp/mirage-mux-test.exe
rm -f /tmp/mirage-mux-test.exe
```

Expected: vet clean, builds, `file` reports a valid PE32+ Windows executable.

- [ ] **Step 6: Commit**

```bash
git add cmd/mirage/main.go cmd/mirage/runclient_test.go
git commit -m "feat: wire session multiplexing into client/server (one handshake per session)"
```

---

---

### Task 3: Manual verification + docs

**Files:**
- Modify: `README.md`, `PROGRESS.md`

- [ ] **Step 1: Manual loopback verification with real binaries**

Build the binary, generate keys, start a local test HTTP server, start
`mirage server` and `mirage client` exactly as in prior manual-verification
rounds (see `PROGRESS.md` for the established pattern: PID files in `/tmp`,
not shell variables, since each Bash invocation is a fresh shell).

Then fire several concurrent `curl` requests through the SAME running
`mirage client` process to DIFFERENT targets (e.g. two different local test
HTTP servers on different ports) and confirm:
1. All requests succeed.
2. The server log shows exactly ONE handshake-related log line group per
   TCP connection (i.e. no repeated "tunnel ->" preceded by repeated
   connection setup — there should be a single underlying session, multiple
   `tunnel ->` lines for the different targets, all attributable to one
   client connection).
3. Bad-PSK and raw-probe fallback still behave exactly as before (rerun
   those two checks too — the handshake-gating logic didn't change).

- [ ] **Step 2: Update README**

Add a verified-properties bullet under "Что проверено (loopback)" describing
the multiplexing check. Mark roadmap item "Мультиплекс" as done, update the
architecture diagram/file list to mention `mux.go`.

- [ ] **Step 3: Update PROGRESS.md**

Add an entry following the established format: what was done, what worked,
what didn't (any issues found and how they were fixed), commit hash.

- [ ] **Step 4: Commit**

```bash
git add README.md PROGRESS.md
git commit -m "docs: reflect session multiplexing in README/PROGRESS.md"
```

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-06-multiplexing.md`.
