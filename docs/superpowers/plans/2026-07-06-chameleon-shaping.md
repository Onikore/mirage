# Chameleon Shaping (Generic Padding) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional periodic padding frames to obscure a session's true
idle/active traffic timing and size signature — a generic obfuscation
primitive, explicitly NOT a precise match to any specific protocol's traffic
profile (no real capture data exists to match against; see the design spec).

**Architecture:** One new frame type in the existing `internal/protocol/mux.go`
frame format (`framePadding`), silently discarded by `readLoop` on receipt.
`Session.StartPadding(...)` is an opt-in background goroutine that sends a
random-size padding frame after a random jittered interval, stopping when
the session closes. `cmd/mirage/main.go` gets one new `-padding` bool flag
(client and server) that turns this on with fixed sensible defaults — no
tuning-flag sprawl for a feature that doesn't claim precision anyway.

**Tech Stack:** stdlib only (`math/rand/v2`, already-available in the
project's Go 1.25 toolchain — no new dependency).

## Global Constraints

- `id=0` is reserved for padding frames — real stream IDs from `Open` start
  at 1 (`atomic.AddUint32(&s.nextID, 1)`, verified never returns 0), so this
  never collides with a real stream.
- Padding frames must never be dispatched to any `Stream` — `readLoop`'s
  `framePadding` case does nothing after the frame's bytes are consumed by
  the existing generic header+payload read logic.
- `StartPadding` is opt-in only — `NewSession` must NOT start it
  automatically, so existing behavior/tests are unaffected unless a caller
  explicitly calls it.
- No new external dependency.

---

### Task 1: `internal/protocol/mux.go` — padding frame type + `StartPadding`

**Files:**
- Modify: `internal/protocol/mux.go`
- Modify: `internal/protocol/mux_test.go`

**Interfaces:**
- Produces (consumed by Task 2):
  `func (s *Session) StartPadding(minInterval, maxInterval time.Duration, minSize, maxSize int)`

- [ ] **Step 1: Add the frame type constant**

In the `const ( frameOpen ... )` block, add:

```go
const (
	frameOpen    byte = 1
	frameData    byte = 2
	frameClose   byte = 3
	framePadding byte = 4 // шум для обфускации трафика; id всегда 0, payload игнорируется получателем
)
```

- [ ] **Step 2: Add the no-op receive case in `readLoop`**

In `readLoop`'s `switch typ {` block, add a case (order doesn't matter,
place it after `frameClose`):

```go
		case framePadding:
			// обфускация трафика -- байты уже вычитаны общей логикой выше
			// (io.ReadFull для payload), больше ничего делать не нужно: это
			// и есть "отбросить".
```

- [ ] **Step 3: Add `writePadding` and `StartPadding`**

Add near the bottom of the `Session` methods (after `shutdown`, before the
`Stream` type):

```go
// writePadding отправляет один кадр-шум размера n. Содержимое (нули) не
// имеет значения: writeFrame пишет в *SecureConn, а AEAD-шифротекст
// неотличим от случайного независимо от plaintext -- пассивному
// наблюдателю снаружи в любом случае виден только шифротекст. Значение
// имеют только размер и тайминг кадра, не его содержимое.
func (s *Session) writePadding(n int) error {
	return s.writeFrame(0, framePadding, make([]byte, n))
}

// StartPadding запускает фоновую заливку случайных padding-кадров: после
// случайного джиттера в [minInterval, maxInterval) шлёт один кадр
// случайного размера в [minSize, maxSize), повторяет, пока сессия не
// закрылась. Не вызывается автоматически из NewSession — включается
// явно вызывающим кодом (см. cmd/mirage/main.go, флаг -padding).
func (s *Session) StartPadding(minInterval, maxInterval time.Duration, minSize, maxSize int) {
	go func() {
		for {
			d := minInterval
			if maxInterval > minInterval {
				d += time.Duration(rand.Int64N(int64(maxInterval - minInterval)))
			}
			select {
			case <-time.After(d):
			case <-s.closed:
				return
			}
			n := minSize
			if maxSize > minSize {
				n += rand.IntN(maxSize - minSize)
			}
			if s.writePadding(n) != nil {
				return // сессия, судя по всему, умерла -- цикл сам завершится
			}
		}
	}()
}
```

Add `"math/rand/v2"` and `"time"` to `mux.go`'s import block (alongside the
existing `encoding/binary`, `io`, `sync`, `sync/atomic`).

- [ ] **Step 4: Write the test**

Add to `mux_test.go`:

```go
func TestPaddingFramesNeverReachApplicationStream(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1)
	server := NewSession(c2)
	server.StartPadding(1*time.Millisecond, 3*time.Millisecond, 8, 16)
	client.StartPadding(1*time.Millisecond, 3*time.Millisecond, 8, 16)

	clientSt, err := client.Open([]byte("target"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	serverSt, _, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	want := []byte("real application data")
	go func() {
		time.Sleep(20 * time.Millisecond) // let a few padding frames interleave first
		serverSt.Write(want)
	}()

	buf := make([]byte, len(want))
	if _, err := io.ReadFull(clientSt, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("got %q, want %q -- a padding frame's bytes leaked into the application stream", buf, want)
	}
}
```

Add `"time"` to `mux_test.go`'s import block.

- [ ] **Step 5: Run tests**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go build ./... && go vet ./... && gofmt -l .
go test ./internal/protocol/... -run TestPaddingFramesNeverReachApplicationStream -race -v -count=5
go test ./... -race
```

Expected: clean build/vet/fmt, new test passes 5/5, full suite green.

- [ ] **Step 6: Commit**

```bash
git add internal/protocol/mux.go internal/protocol/mux_test.go
git commit -m "feat: add optional padding frames to obscure traffic timing/size (mux.go)"
```

---

### Task 2: `-padding` CLI flag + manual verification + docs

**Files:**
- Modify: `cmd/mirage/main.go`
- Modify: `README.md`, `PROGRESS.md`

**Interfaces:**
- Consumes: `(*protocol.Session).StartPadding(minInterval, maxInterval time.Duration, minSize, maxSize int)` from Task 1.

This task requires judgment about where in the existing control flow to
thread a new bool through (`serveConn`'s parameter list, `cmdServer`'s flag
parsing, `cmdClient`'s flag parsing) — read the current file before editing,
don't guess line numbers.

- [ ] **Step 1: Add the flag and wire it through, server side**

In `cmdServer`, add a flag:

```go
padding := fs.Bool("padding", false, "add periodic random-size padding frames to obscure session timing/size patterns (generic obfuscation, not a precise protocol-profile match)")
```

Thread `*padding` through to `serveConn` (add a `padding bool` parameter to
`serveConn`'s signature, update its one call site in the accept loop). In
`serveConn`, right after `sess := protocol.NewSession(sc)`:

```go
	sess := protocol.NewSession(sc)
	if padding {
		sess.StartPadding(1*time.Second, 5*time.Second, 32, 256)
	}
```

- [ ] **Step 2: Add the flag and wire it through, client side**

In `cmdClient`, add the same flag:

```go
padding := fs.Bool("padding", false, "add periodic random-size padding frames to obscure session timing/size patterns (generic obfuscation, not a precise protocol-profile match)")
```

After establishing the session (`sess := protocol.NewSession(sc)`):

```go
	sess := protocol.NewSession(sc)
	if *padding {
		sess.StartPadding(1*time.Second, 5*time.Second, 32, 256)
	}
```

- [ ] **Step 3: Build and test**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
go build ./... && go vet ./... && gofmt -l . && go test ./... -race
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/mirage-padding-test.exe ./cmd/mirage
file /tmp/mirage-padding-test.exe
rm -f /tmp/mirage-padding-test.exe
```

Expected: everything clean, valid Windows PE executable.

- [ ] **Step 4: Manual verification with real binaries**

Build the binary, generate keys, start a local test HTTP server, start
`mirage server -padding` and `mirage client -padding` (both flagged on),
confirm normal request/response traffic still works correctly end-to-end
through curl+SOCKS5 (padding frames must be fully transparent to
application data). Also re-verify bad-PSK and raw-probe fallback are
unaffected (they're gated before session/padding even exists).

- [ ] **Step 5: Update README and PROGRESS.md**

Add a verified-properties bullet describing the padding check. Mark
"Chameleon shaping" done in the roadmap with the explicit caveat that this
is generic obfuscation, not a measured protocol-profile match (matches the
design spec's own framing — don't overstate it). Update PROGRESS.md with
the standard what-worked/what-didn't entry.

- [ ] **Step 6: Commit**

```bash
git add cmd/mirage/main.go README.md PROGRESS.md
git commit -m "feat: -padding flag for client/server; docs"
```

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-06-chameleon-shaping.md`.
