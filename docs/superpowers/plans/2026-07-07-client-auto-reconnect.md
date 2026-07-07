# Client Auto-Reconnect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the mirage client's established session to the server dies
(idle timeout, network blip, server restart), the client (CLI and both
GUIs) automatically redials and re-handshakes instead of requiring a manual
process restart / Disconnect-Connect click.

**Architecture:** One additive public surface on `internal/protocol.Session`
(`Done()`, `Err()`, `Close()` — all thin wrappers around fields that already
exist privately). One new type, `sessionHolder` (`cmd/mirage/reconnect.go`),
that owns a `*protocol.Session` behind a mutex, watches `Done()`, and redials
via an injected `dial func() (*protocol.Session, error)` closure with growing
backoff, unbounded retries. CLI and both GUIs swap their direct
`*protocol.Session` usage for `*sessionHolder` and wire its status callback
to their existing log/label.

**Tech Stack:** stdlib only (`sync`, `time`, `net`, `fmt`) — no new
dependency. Reuses the already-added `fyne.io/fyne/v2` (Linux GUI) and
`github.com/lxn/walk` (Windows GUI) only for UI-thread marshaling
(`fyne.Do`, `mw.Synchronize`), nothing new.

## Global Constraints

- First connect (before any session has ever been established) stays
  fail-fast: `log.Fatal` in CLI, inline error display in GUI — auto-reconnect
  only ever engages after a session that was once alive dies. This is
  enforced by construction, not a runtime check: `newSessionHolder` always
  takes an already-successfully-established `initial *protocol.Session`.
- Retries are unbounded — no max-attempts cap. Backoff starts at
  `minBackoff`, doubles each failed attempt, caps at `maxBackoff`. Real
  callers (CLI, both GUIs) use `1*time.Second` / `30*time.Second`. Tests use
  millisecond-scale values (this is why `minBackoff`/`maxBackoff` are
  explicit constructor parameters, not hardcoded constants).
- While no session is current (mid-reconnect), new local SOCKS5 connections
  fail immediately — no queueing, no waiting. `sessionHolder.Current()`
  returns `nil` in this window; callers must close the local connection
  right away when they see `nil`.
- `sessionHolder.Stop()` must not block on an in-flight `dial()` call (GUI
  Disconnect must stay responsive even if a redial attempt is in progress) —
  see Task 2 for the exact non-blocking-Stop mechanism.
- `internal/protocol/mux.go`'s existing logic (frame handling, backpressure,
  the two-channel stream-close design) is not modified — only additive
  exported methods are added.
- GUI status updates from the reconnect background goroutine must be
  marshaled onto the UI thread: `mw.Synchronize(...)` for `lxn/walk`
  (Windows), `fyne.Do(...)` for Fyne (Linux) — both already confirmed
  available in the versions this project uses.

## Files

- Modify: `internal/protocol/mux.go` (add `Done()`, `Err()`, `Close()`)
- Modify: `internal/protocol/mux_test.go` (tests for the above)
- Create: `cmd/mirage/reconnect.go` (`sessionHolder` type, `dialSession` helper)
- Create: `cmd/mirage/reconnect_test.go`
- Modify: `cmd/mirage/main.go` (`cmdClient`, `runClientListener`, `clientConn`)
- Modify: `cmd/mirage/runclient_test.go` (signature change: `*protocol.Session` → `*sessionHolder`)
- Modify: `cmd/mirage/gui_windows.go`
- Modify: `cmd/mirage/gui_linux.go`
- Modify: `README.md`, `PROGRESS.md`

---

### Task 1: `internal/protocol/mux.go` — `Done()`, `Err()`, `Close()`

**Files:**
- Modify: `internal/protocol/mux.go`
- Modify: `internal/protocol/mux_test.go`

**Interfaces:**
- Produces (consumed by Task 2):
  `func (s *Session) Done() <-chan struct{}`
  `func (s *Session) Err() error`
  `func (s *Session) Close() error`

- [ ] **Step 1: Write the failing tests**

Add to `internal/protocol/mux_test.go` (file already imports `net`, `time`,
`testing` — no new imports needed):

```go
func TestSessionDoneAndErr(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession(c1)

	select {
	case <-sess.Done():
		t.Fatal("Done() closed before the session died")
	default:
	}
	if err := sess.Err(); err != nil {
		t.Fatalf("Err() should be nil while alive, got %v", err)
	}

	c2.Close()

	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() did not close after the underlying connection closed")
	}
	if sess.Err() == nil {
		t.Fatal("Err() should be non-nil after the session died")
	}
}

func TestSessionClose(t *testing.T) {
	c1, _ := net.Pipe()
	sess := NewSession(c1)

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() did not close after Close()")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go test ./internal/protocol/... -run 'TestSessionDoneAndErr|TestSessionClose' -v
```

Expected: FAIL — `s.Done undefined`, `s.Err undefined`, `s.Close undefined`.

- [ ] **Step 3: Implement**

In `internal/protocol/mux.go`, add these three methods right after the
existing `shutdown` method (which manages the same `s.closed`/`s.closeErr`
fields these wrap) and before `writePadding`:

```go
// Done возвращает канал, который закрывается, когда сессия умерла (обрыв
// соединения, чтение вернуло ошибку) -- тот же сигнал, которым уже
// пользуется внутренний shutdown().
func (s *Session) Done() <-chan struct{} {
	return s.closed
}

// Err возвращает причину закрытия сессии, либо nil, пока сессия жива.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// Close закрывает базовое соединение сессии -- readLoop получит ошибку
// чтения и сам вызовет shutdown() (безопасно вызывать даже после того,
// как сессия уже умерла естественным путём -- shutdown() идемпотентен,
// см. его собственную реализацию выше).
func (s *Session) Close() error {
	return s.conn.Close()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go test ./internal/protocol/... -run 'TestSessionDoneAndErr|TestSessionClose' -v -race
go test ./internal/protocol/... -race
```

Expected: both new tests PASS, full package suite still green.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/mux.go internal/protocol/mux_test.go
git commit -m "feat: export Session.Done/Err/Close for client-side reconnect"
```

---

### Task 2: `cmd/mirage/reconnect.go` — `sessionHolder` + `dialSession`

**Files:**
- Create: `cmd/mirage/reconnect.go`
- Create: `cmd/mirage/reconnect_test.go`

**Interfaces:**
- Consumes: `(*protocol.Session).Done() <-chan struct{}`, `.Err() error`,
  `.Close() error` from Task 1; `protocol.ClientHandshake`,
  `protocol.NewSession`, `(*protocol.Session).StartPadding` (already exist).
- Produces (consumed by Task 3 and Task 4):
  `func dialSession(server string, pub, psk []byte, sni string, padding bool) (*protocol.Session, error)`
  `func newSessionHolder(initial *protocol.Session, dial func() (*protocol.Session, error), onStatus func(string), minBackoff, maxBackoff time.Duration) *sessionHolder`
  `func (h *sessionHolder) Current() *protocol.Session`
  `func (h *sessionHolder) Stop()`

- [ ] **Step 1: Write the failing tests**

Create `cmd/mirage/reconnect_test.go`:

```go
package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"mirage/internal/protocol"
)

// TestSessionHolderReconnectsAfterDeath drives dial() with a channel so the
// test controls exactly when each attempt resolves -- this lets it assert
// Current()==nil mid-reconnect deterministically instead of racing timers.
func TestSessionHolderReconnectsAfterDeath(t *testing.T) {
	c1, c2 := net.Pipe()
	sess1 := protocol.NewSession(c1)

	attemptStarted := make(chan struct{})
	result := make(chan error)

	dial := func() (*protocol.Session, error) {
		attemptStarted <- struct{}{}
		if err := <-result; err != nil {
			return nil, err
		}
		nc1, _ := net.Pipe()
		return protocol.NewSession(nc1), nil
	}

	h := newSessionHolder(sess1, dial, nil, time.Millisecond, 5*time.Millisecond)
	defer h.Stop()

	if h.Current() != sess1 {
		t.Fatalf("Current() before death should be the initial session")
	}

	c2.Close() // убивает sess1 -- readLoop получит ошибку чтения

	<-attemptStarted // первая попытка началась
	if cur := h.Current(); cur != nil {
		t.Fatalf("Current() should be nil while reconnecting, got %v", cur)
	}
	result <- errors.New("simulated dial failure")

	<-attemptStarted // вторая попытка
	result <- nil // на этот раз успех

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur := h.Current(); cur != nil && cur != sess1 {
			return // успех
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("sessionHolder did not install the new session after a successful dial")
}

// TestSessionHolderStopDuringDialDoesNotResurrectSession guards the
// non-blocking-Stop design: Disconnect while a redial is in flight must not
// let that redial's result become the current session afterward.
func TestSessionHolderStopDuringDialDoesNotResurrectSession(t *testing.T) {
	c1, c2 := net.Pipe()
	sess1 := protocol.NewSession(c1)

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})

	dial := func() (*protocol.Session, error) {
		close(dialStarted)
		<-releaseDial
		nc1, _ := net.Pipe()
		return protocol.NewSession(nc1), nil
	}

	h := newSessionHolder(sess1, dial, nil, time.Millisecond, time.Millisecond)
	c2.Close() // убивает sess1 -- запускает dial()

	<-dialStarted
	h.Stop() // Disconnect ровно во время dial()
	close(releaseDial) // теперь dial() вернёт успех

	time.Sleep(20 * time.Millisecond) // дать run() шанс (ошибочно) установить сессию
	if cur := h.Current(); cur != nil {
		t.Fatalf("Current() should stay nil after Stop() during an in-flight dial, got %v", cur)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go test ./cmd/mirage/... -run TestSessionHolder -v
```

Expected: FAIL to compile — `newSessionHolder`/`sessionHolder` undefined.

- [ ] **Step 3: Implement**

Create `cmd/mirage/reconnect.go`:

```go
package main

// reconnect.go -- sessionHolder переустанавливает клиентскую сессию с
// растущей паузой, когда текущая умирает (см. design spec:
// docs/superpowers/specs/2026-07-07-client-auto-reconnect-design.md).
// Первый коннект (до создания sessionHolder) остаётся fail-fast -- эта
// обёртка начинает работать только с уже установленной сессией.

import (
	"fmt"
	"net"
	"sync"
	"time"

	"mirage/internal/protocol"
)

// dialSession устанавливает одно TCP-соединение до сервера, проводит
// клиентское рукопожатие и оборачивает результат в *protocol.Session --
// используется и для самого первого коннекта (CLI, оба GUI), и как
// dial-замыкание для sessionHolder при переподключении.
func dialSession(server string, pub, psk []byte, sni string, padding bool) (*protocol.Session, error) {
	up, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	sc, err := protocol.ClientHandshake(up, pub, psk, sni)
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	up.SetDeadline(time.Time{})
	sess := protocol.NewSession(sc)
	if padding {
		sess.StartPadding(1*time.Second, 5*time.Second, 32, 256)
	}
	return sess, nil
}

type sessionHolder struct {
	mu         sync.Mutex
	sess       *protocol.Session // nil, пока идёт передозвон
	dial       func() (*protocol.Session, error)
	onStatus   func(string)
	minBackoff time.Duration
	maxBackoff time.Duration
	stopCh     chan struct{}
	stopOnce   sync.Once
}

// newSessionHolder запускает фоновую горутину, которая следит за initial и
// при её смерти переустанавливает сессию через dial с растущей паузой
// (minBackoff, удвоение, потолок maxBackoff), без ограничения по числу
// попыток. onStatus вызывается на каждое изменение статуса (умерла сессия,
// неудачная попытка, успешный реконнект); может быть nil.
func newSessionHolder(initial *protocol.Session, dial func() (*protocol.Session, error), onStatus func(string), minBackoff, maxBackoff time.Duration) *sessionHolder {
	if onStatus == nil {
		onStatus = func(string) {}
	}
	h := &sessionHolder{
		sess:       initial,
		dial:       dial,
		onStatus:   onStatus,
		minBackoff: minBackoff,
		maxBackoff: maxBackoff,
		stopCh:     make(chan struct{}),
	}
	go h.run(initial)
	return h
}

func (h *sessionHolder) run(sess *protocol.Session) {
	for {
		select {
		case <-sess.Done():
		case <-h.stopCh:
			return
		}
		h.onStatus(fmt.Sprintf("session died: %v -- reconnecting", sess.Err()))
		h.mu.Lock()
		h.sess = nil
		h.mu.Unlock()

		backoff := h.minBackoff
		attempt := 0
		for {
			attempt++
			newSess, err := h.dial()
			if err != nil {
				h.onStatus(fmt.Sprintf("reconnect attempt %d failed: %v", attempt, err))
				select {
				case <-time.After(backoff):
				case <-h.stopCh:
					return
				}
				backoff *= 2
				if backoff > h.maxBackoff {
					backoff = h.maxBackoff
				}
				continue
			}

			select {
			case <-h.stopCh:
				// Disconnect случился, пока шёл dial() -- закрыть только
				// что установленную сессию и выйти, не публикуя её (Stop()
				// не блокируется на dial(), см. Global Constraints).
				newSess.Close()
				return
			default:
			}

			h.mu.Lock()
			h.sess = newSess
			h.mu.Unlock()
			h.onStatus("reconnected")
			sess = newSess
			break
		}
	}
}

// Current возвращает текущую сессию, либо nil, если прямо сейчас идёт
// передозвон -- вызывающий код (clientConn) должен сразу отказать новому
// локальному подключению, а не ждать.
func (h *sessionHolder) Current() *protocol.Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sess
}

// Stop останавливает цикл переподключения и закрывает текущую сессию. Не
// блокируется на активной попытке dial() -- run() сам заметит стоп и
// закроет только что установленную сессию после возврата из dial(), вместо
// того чтобы держать вызывающего (GUI Disconnect) замороженным на время
// таймаута dial().
func (h *sessionHolder) Stop() {
	h.stopOnce.Do(func() { close(h.stopCh) })
	h.mu.Lock()
	sess := h.sess
	h.sess = nil
	h.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go test ./cmd/mirage/... -run TestSessionHolder -v -race -count=5
```

Expected: both tests PASS 5/5 (repeat count guards against flakiness in the
channel-driven synchronization).

- [ ] **Step 5: Commit**

```bash
git add cmd/mirage/reconnect.go cmd/mirage/reconnect_test.go
git commit -m "feat: sessionHolder for client-side auto-reconnect"
```

---

### Task 3: CLI integration (`cmd/mirage/main.go`)

**Files:**
- Modify: `cmd/mirage/main.go`
- Modify: `cmd/mirage/runclient_test.go`

**Interfaces:**
- Consumes: `dialSession`, `newSessionHolder`, `(*sessionHolder).Current()`,
  `(*sessionHolder).Stop()` from Task 2.
- Produces (consumed by Task 4): `runClientListener(ln net.Listener, h *sessionHolder)`,
  `clientConn(c net.Conn, h *sessionHolder)` — same names, new parameter type.

- [ ] **Step 1: Update `runclient_test.go` for the new signature**

The existing test constructs a bare `*protocol.Session` and passes it
directly to `runClientListener` — that call site must wrap it in a
`sessionHolder` once the signature changes. Replace the whole file:

```go
package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"mirage/internal/protocol"
)

// runClientListener must return promptly once its listener is closed — this
// is exactly the contract the GUI's "Disconnect" button relies on.
func TestRunClientListenerReturnsWhenListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c1, _ := net.Pipe()
	sess := protocol.NewSession(c1)
	h := newSessionHolder(sess, func() (*protocol.Session, error) {
		return nil, errors.New("dial should not be called in this test")
	}, nil, time.Millisecond, time.Millisecond)
	defer h.Stop()

	done := make(chan struct{})
	go func() {
		runClientListener(ln, h)
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

- [ ] **Step 2: Run test to verify it fails**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go build ./cmd/mirage/... 2>&1 | head -20
```

Expected: compile error — `runClientListener(ln, h)` doesn't match the
current `runClientListener(ln net.Listener, sess *protocol.Session)`.

- [ ] **Step 3: Implement — update `cmd/mirage/main.go`**

Replace the whole client section (currently `cmdClient`, `runClientListener`,
`clientConn` — the block starting at `// ---------------- client ----------------`
through the end of the file):

```go
// ---------------- client ----------------

func cmdClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listen")
	server := fs.String("server", "", "mirage server HOST:PORT")
	pubHex := fs.String("pub", "", "server public key (hex)")
	pskHex := fs.String("psk", "", "pre-shared key (hex)")
	sni := fs.String("sni", "www.google.com", "SNI hostname to wear in the disguised ClientHello")
	padding := fs.Bool("padding", false, "add periodic random-size padding frames to obscure session timing/size patterns (generic obfuscation, not a precise protocol-profile match)")
	fs.Parse(args)

	pub := mustHex(*pubHex)
	psk := mustHex(*pskHex)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}

	// Первый коннект остаётся fail-fast -- если сервер недоступен или
	// рукопожатие не проходит уже при старте, процесс завершается сразу, а
	// не поднимает SOCKS5 вслепую (см. design spec, Global Constraints).
	sess, err := dialSession(*server, pub, psk, *sni, *padding)
	if err != nil {
		log.Fatal(err)
	}

	dial := func() (*protocol.Session, error) {
		return dialSession(*server, pub, psk, *sni, *padding)
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
	host, port, err := socks.Accept(c)
	if err != nil {
		return
	}

	sess := h.Current()
	if sess == nil {
		// Сессия прямо сейчас недоступна (идёт автопереподключение) --
		// сразу отказать, не ждать (см. design spec).
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

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go build ./... && go vet ./... && gofmt -l .
go test ./... -race
```

Expected: clean build/vet/fmt, full suite green (including the updated
`TestRunClientListenerReturnsWhenListenerClosed` and Task 2's new tests).

- [ ] **Step 5: Commit**

```bash
git add cmd/mirage/main.go cmd/mirage/runclient_test.go
git commit -m "feat: wire CLI client through sessionHolder for auto-reconnect"
```

---

### Task 4: GUI integration (Windows + Linux) + manual verification + docs

**Files:**
- Modify: `cmd/mirage/gui_windows.go`
- Modify: `cmd/mirage/gui_linux.go`
- Modify: `README.md`, `PROGRESS.md`

**Interfaces:**
- Consumes: `dialSession`, `newSessionHolder`, `(*sessionHolder).Stop()`,
  `runClientListener(ln, h *sessionHolder)` from Tasks 2 and 3.

Both GUIs get the same structural change: replace the direct
`net.DialTimeout` + `protocol.ClientHandshake` + `protocol.NewSession` +
raw `sessConn io.Closer` tracking with `dialSession` for the first connect
and a `*sessionHolder` for everything after, with status updates marshaled
onto each toolkit's UI thread.

- [ ] **Step 1: Rewrite `cmd/mirage/gui_windows.go`**

```go
//go:build windows

package main

// gui_windows.go — минимальный GUI-клиент (как обычное VPN-приложение):
// поля для сервера/ключей, кнопка Connect/Disconnect, статус. Только
// Windows — github.com/lxn/walk оборачивает Win32 напрямую (без cgo), не
// собирается на других GOOS в принципе. См. gui_linux.go (Fyne) и
// gui_other.go для остальных платформ.
//
// Переиспользует ровно тот же клиентский код, что и `mirage client`
// (runClientListener/clientConn в main.go) и то же автопереподключение
// (sessionHolder в reconnect.go) — GUI лишь запускает/останавливает тот же
// слушатель по кнопке и показывает статус, ничего не дублирует.

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"mirage/internal/protocol"
)

func cmdGUI() {
	cfg, _ := loadGUIConfig() // пустой конфиг при первом запуске — не ошибка
	if cfg.SNI == "" {
		cfg.SNI = "www.google.com"
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}

	var (
		mw                                                 *walk.MainWindow
		serverEdit, pubEdit, pskEdit, sniEdit, listenEdit *walk.LineEdit
		connectBtn                                        *walk.PushButton
		statusLbl                                          *walk.Label
		listener                                           net.Listener
		holder                                             *sessionHolder
	)

	setStatus := func(s string) {
		mw.Synchronize(func() { statusLbl.SetText(s) })
	}

	connect := func() {
		server, pubHex, pskHex, sni, listenAddr :=
			serverEdit.Text(), pubEdit.Text(), pskEdit.Text(), sniEdit.Text(), listenEdit.Text()

		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			statusLbl.SetText("Bad server pubkey: " + err.Error())
			return
		}
		psk, err := hex.DecodeString(pskHex)
		if err != nil {
			statusLbl.SetText("Bad PSK: " + err.Error())
			return
		}

		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			statusLbl.SetText("Listen error: " + err.Error())
			return
		}

		sess, err := dialSession(server, pub, psk, sni, false)
		if err != nil {
			statusLbl.SetText(err.Error())
			ln.Close()
			return
		}

		listener = ln
		holder = newSessionHolder(sess, func() (*protocol.Session, error) {
			return dialSession(server, pub, psk, sni, false)
		}, setStatus, 1*time.Second, 30*time.Second)
		go runClientListener(ln, holder)

		guiConfig{Server: server, Pub: pubHex, PSK: pskHex, SNI: sni, Listen: listenAddr}.save()

		statusLbl.SetText(fmt.Sprintf("Connected: SOCKS5 %s -> %s", listenAddr, server))
		connectBtn.SetText("Disconnect")
	}

	disconnect := func() {
		if listener != nil {
			listener.Close()
			listener = nil
		}
		if holder != nil {
			holder.Stop()
			holder = nil
		}
		statusLbl.SetText("Idle")
		connectBtn.SetText("Connect")
	}

	_, err := MainWindow{
		AssignTo: &mw,
		Title:    "Mirage",
		Size:     Size{Width: 440, Height: 300},
		Layout:   VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Server (host:port):"},
					LineEdit{AssignTo: &serverEdit, Text: cfg.Server},
					Label{Text: "Server pubkey (hex):"},
					LineEdit{AssignTo: &pubEdit, Text: cfg.Pub},
					Label{Text: "PSK (hex):"},
					LineEdit{AssignTo: &pskEdit, Text: cfg.PSK, PasswordMode: true},
					Label{Text: "SNI:"},
					LineEdit{AssignTo: &sniEdit, Text: cfg.SNI},
					Label{Text: "Local SOCKS5 (host:port):"},
					LineEdit{AssignTo: &listenEdit, Text: cfg.Listen},
				},
			},
			PushButton{
				AssignTo: &connectBtn,
				Text:     "Connect",
				OnClicked: func() {
					if listener == nil {
						connect()
					} else {
						disconnect()
					}
				},
			},
			Label{AssignTo: &statusLbl, Text: "Idle"},
		},
	}.Run()
	if err != nil {
		// Окно не создалось (например, нет манифеста Common-Controls v6 в
		// exe) — виджеты не назначены, дальше вызывать disconnect() нельзя,
		// упадёт на nil-указателе.
		fmt.Fprintln(os.Stderr, "mirage gui: window creation failed:", err)
		return
	}

	disconnect() // окно закрыли — прибрать слушатель за собой
}
```

- [ ] **Step 2: Rewrite `cmd/mirage/gui_linux.go`**

```go
//go:build linux

package main

// gui_linux.go — минимальный GUI-клиент под Linux (Fyne): те же поля и та
// же логика connect/disconnect, что и в gui_windows.go, но на
// кроссплатформенном тулките — lxn/walk оборачивает Win32 напрямую и на
// Linux не собирается в принципе. Переиспользует ровно тот же клиентский
// код (runClientListener/clientConn в main.go) и то же автопереподключение
// (sessionHolder в reconnect.go), что и `mirage client` и Windows GUI —
// ничего не дублирует.

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"mirage/internal/protocol"
)

func cmdGUI() {
	cfg, _ := loadGUIConfig() // пустой конфиг при первом запуске — не ошибка
	if cfg.SNI == "" {
		cfg.SNI = "www.google.com"
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}

	a := app.New()
	w := a.NewWindow("Mirage")

	serverEntry := widget.NewEntry()
	serverEntry.SetText(cfg.Server)
	pubEntry := widget.NewEntry()
	pubEntry.SetText(cfg.Pub)
	pskEntry := widget.NewPasswordEntry()
	pskEntry.SetText(cfg.PSK)
	sniEntry := widget.NewEntry()
	sniEntry.SetText(cfg.SNI)
	listenEntry := widget.NewEntry()
	listenEntry.SetText(cfg.Listen)

	status := widget.NewLabel("Idle")

	var (
		listener   net.Listener
		holder     *sessionHolder
		connectBtn *widget.Button
	)

	setStatus := func(s string) {
		fyne.Do(func() { status.SetText(s) })
	}

	connect := func() {
		server, pubHex, pskHex, sni, listenAddr :=
			serverEntry.Text, pubEntry.Text, pskEntry.Text, sniEntry.Text, listenEntry.Text

		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			status.SetText("Bad server pubkey: " + err.Error())
			return
		}
		psk, err := hex.DecodeString(pskHex)
		if err != nil {
			status.SetText("Bad PSK: " + err.Error())
			return
		}

		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			status.SetText("Listen error: " + err.Error())
			return
		}

		sess, err := dialSession(server, pub, psk, sni, false)
		if err != nil {
			status.SetText(err.Error())
			ln.Close()
			return
		}

		listener = ln
		holder = newSessionHolder(sess, func() (*protocol.Session, error) {
			return dialSession(server, pub, psk, sni, false)
		}, setStatus, 1*time.Second, 30*time.Second)
		go runClientListener(ln, holder)

		guiConfig{Server: server, Pub: pubHex, PSK: pskHex, SNI: sni, Listen: listenAddr}.save()

		status.SetText(fmt.Sprintf("Connected: SOCKS5 %s -> %s", listenAddr, server))
		connectBtn.SetText("Disconnect")
	}

	disconnect := func() {
		if listener != nil {
			listener.Close()
			listener = nil
		}
		if holder != nil {
			holder.Stop()
			holder = nil
		}
		status.SetText("Idle")
		connectBtn.SetText("Connect")
	}

	connectBtn = widget.NewButton("Connect", func() {
		if listener == nil {
			connect()
		} else {
			disconnect()
		}
	})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Server (host:port):"), serverEntry,
		widget.NewLabel("Server pubkey (hex):"), pubEntry,
		widget.NewLabel("PSK (hex):"), pskEntry,
		widget.NewLabel("SNI:"), sniEntry,
		widget.NewLabel("Local SOCKS5 (host:port):"), listenEntry,
		connectBtn,
		status,
	))
	w.Resize(fyne.NewSize(420, 380))
	w.SetOnClosed(disconnect) // окно закрыли — прибрать слушатель за собой

	w.ShowAndRun()
}
```

- [ ] **Step 3: Build, vet, format, test — Linux**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go build ./... && go vet ./... && gofmt -l .
go test ./... -race
```

Expected: clean build/vet/fmt, full suite green.

- [ ] **Step 4: Cross-compile and vet — Windows**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-H windowsgui" -o /tmp/mirage-gui-check.exe ./cmd/mirage
file /tmp/mirage-gui-check.exe
rm -f /tmp/mirage-gui-check.exe
```

Expected: clean vet, valid Windows PE executable. (No live Windows machine
available for this task — this confirms the code compiles and type-checks
correctly for `GOOS=windows`; the live-hardware check already happened
earlier this project for the base GUI and is not re-run here since this
task doesn't touch anything Windows-manifest-related.)

- [ ] **Step 5: Manual end-to-end verification — Linux GUI, real reconnect**

Build and run the real Linux GUI binary against the already-deployed VPS
mirage server, then force a real session death and confirm auto-recovery:

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go build -o /tmp/mirage-gui-linux ./cmd/mirage
DISPLAY=:1 /tmp/mirage-gui-linux gui &
```

1. Click Connect (fields already pre-filled from the earlier session's
   `~/.config/mirage/gui-config.json`) — status should read
   `Connected: SOCKS5 127.0.0.1:1080 -> <VPS>:8443`.
2. Verify the tunnel works: `curl --socks5-hostname 127.0.0.1:1080 -sS -o /dev/null -w "%{http_code}\n" https://example.com/` → expect `200`.
3. On the VPS, kill the session from the server side to force a death the
   client will actually observe (a TCP RST, not just stopping the process,
   so the client's read fails promptly): `ssh root@<VPS_IP> 'systemctl restart mirage'`.
4. Watch the GUI status label — expect it to move through
   `session died: ..., reconnecting` → possibly one or more
   `reconnect attempt N failed: ...` → `reconnected`, without any manual
   Disconnect/Connect click.
5. Re-run the `curl` from step 2 — expect `200` again, without touching the GUI.
6. While a reconnect attempt is deliberately slow (optional stress check):
   click Disconnect mid-attempt and confirm the GUI does not freeze for the
   full backoff/dial duration (validates the non-blocking `Stop()` from
   Task 2).

Expected: client recovers on its own; no step requires restarting the
client process or manually reconnecting.

- [ ] **Step 6: Update `README.md` and `PROGRESS.md`**

In `README.md`, find the client section describing the "one handshake per
process, not per request" behavior and its stated limitation (the
disclaimer noting the client does NOT reconnect on its own — search for
"клиент её сам не переустанавливает"). Replace that limitation with a
description of the new behavior: the client now auto-reconnects with
growing backoff (1s → 30s cap, unbounded retries) after an established
session dies; the very first connect at process/GUI-Connect start remains
fail-fast (no retry) so config typos surface immediately; while a reconnect
is in progress, new local SOCKS5 requests fail immediately rather than
queueing.

Add a new dated entry to `PROGRESS.md` (matching the existing style of
prior entries — see `## 2026-07-06 — Chameleon shaping: ...` for the
format) describing what was built, what was verified manually, and any
known trade-off (the bounded-leak edge case: if Disconnect happens to land
exactly while a redial is in flight, that redial's session gets opened and
then immediately closed rather than never opened at all — harmless, just
worth a line).

- [ ] **Step 7: Commit**

```bash
git add cmd/mirage/gui_windows.go cmd/mirage/gui_linux.go README.md PROGRESS.md
git commit -m "feat: wire both GUIs through sessionHolder for auto-reconnect"
```

## Execution Handoff

Plan complete and saved to
`docs/superpowers/plans/2026-07-07-client-auto-reconnect.md`.
