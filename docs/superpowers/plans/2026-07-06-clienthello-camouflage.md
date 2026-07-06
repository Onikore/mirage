# ClientHello Camouflage (uTLS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wrap the mirage client's first handshake message in a real,
uTLS-generated Chrome ClientHello so the wire bytes no longer look like a
bare X25519 key to passive DPI/entropy detectors.

**Architecture:** New file `camouflage.go` builds/parses a Chrome-fingerprint
`ClientHello` via `github.com/refraction-networking/utls`, smuggling our
existing X25519 ephemeral pubkey into the TLS `key_share` extension and our
16-byte handshake auth tag into the `session_id` field (both already
plausible-looking real-Chrome byte shapes — no new wire fields). `handshake.go`
calls these instead of writing/reading the raw 48-byte blob for msg1 only;
msg2 (server → client) is untouched. Anti-probe fallback keeps working
because the parser always returns exactly the bytes it actually consumed,
even on error.

**Tech Stack:** Go 1.24+ (toolchain: `~/sdk/go1.26.4/bin/go` — add to PATH
with `export PATH=$HOME/sdk/go1.26.4/bin:$PATH` if not already on it),
`github.com/refraction-networking/utls` v1.8.2.

## Global Constraints

- Server's response (msg2) is NOT wrapped in TLS framing this iteration — documented limitation, not a bug.
- `parseMimicClientHello` must return every byte actually read (`consumed`) on every error path — the anti-probe fallback in `main.go`'s `fallback()` replays exactly this slice to `dest`. A regression here is a detectability regression, not just a test failure.
- Max accepted mimicked-ClientHello length: 8192 bytes (real Chrome+PQ-hybrid hellos run ~1.5KB; this just bounds allocation for hostile input).
- No changes to `socks.go`, `addr.go`, `frame.go`, `crypto.go` — out of scope.

---

### Task 1: Add the uTLS dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum` (generated)

**Interfaces:**
- Produces: `github.com/refraction-networking/utls` v1.8.2 importable as `tls "github.com/refraction-networking/utls"` in later tasks.

- [ ] **Step 1: Fetch the dependency**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
cd /home/dmitry/Desktop/mirage
go get github.com/refraction-networking/utls@v1.8.2
```

Expected: `go.mod` gains a `require github.com/refraction-networking/utls v1.8.2` line (plus its transitive deps: `andybalholm/brotli`, `klauspost/compress`, `golang.org/x/crypto`, `golang.org/x/sys`), and the `go` directive moves to `go 1.24` (utls's own go.mod floor). `go.sum` is created/updated.

- [ ] **Step 2: Verify the project still builds**

```bash
go build ./...
```

Expected: exits 0, no output (nothing imports utls yet, so this just confirms the module graph resolves).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add uTLS dependency for ClientHello camouflage"
```

---

### Task 2: `camouflage.go` — build and parse the mimicked ClientHello (TDD)

**Files:**
- Create: `camouflage.go`
- Test: `camouflage_test.go`

**Interfaces:**
- Consumes: nothing from other project files (only stdlib + utls).
- Produces:
  - `buildMimicClientHello(sni string, ecPub, tag1 []byte) ([]byte, error)` — used by Task 3's `clientHandshake`.
  - `parseMimicClientHello(r io.Reader) (ecPub, tag1, consumed []byte, err error)` — used by Task 3's `serverHandshake`.

- [ ] **Step 1: Write the failing tests**

Create `camouflage_test.go`:

```go
package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMimicClientHelloRoundTrip(t *testing.T) {
	ecPub := make([]byte, 32)
	rand.Read(ecPub)
	tag1 := make([]byte, 16)
	rand.Read(tag1)

	raw, err := buildMimicClientHello("www.google.com", ecPub, tag1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	gotPub, gotTag, consumed, err := parseMimicClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(gotPub, ecPub) {
		t.Errorf("ecPub mismatch: got %x want %x", gotPub, ecPub)
	}
	if !bytes.Equal(gotTag, tag1) {
		t.Errorf("tag1 mismatch: got %x want %x", gotTag, tag1)
	}
	if len(consumed) != len(raw) {
		t.Errorf("consumed %d bytes, want %d (full record)", len(consumed), len(raw))
	}
}

func TestParseMimicClientHelloGarbage(t *testing.T) {
	_, _, consumed, err := parseMimicClientHello(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")))
	if err == nil {
		t.Fatal("expected error for non-TLS input")
	}
	if len(consumed) == 0 {
		t.Fatal("expected consumed bytes for fallback replay")
	}
}

func TestParseMimicClientHelloShortRead(t *testing.T) {
	// Prober sends 2 bytes then closes the connection (EOF).
	in := []byte{0x16, 0x03}
	_, _, consumed, err := parseMimicClientHello(bytes.NewReader(in))
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
	if !bytes.Equal(consumed, in) {
		t.Errorf("consumed = % x, want exactly % x (no zero-padding)", consumed, in)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./... -run TestMimicClientHello -v
go test ./... -run TestParseMimicClientHello -v
```

Expected: FAIL — `buildMimicClientHello` / `parseMimicClientHello` undefined.

- [ ] **Step 3: Write the implementation**

Create `camouflage.go`:

```go
package main

// camouflage.go — обёртка client->server рукопожатия в мимикрированный
// TLS 1.3 ClientHello (fingerprint Chrome, через uTLS), чтобы первый байт
// на проводе не палился энтропийным/форматным детектором как "голый" X25519.
//
// Наш X25519 ephemeral pubkey едет как есть в key_share-расширении (формат
// совпадает 1-в-1, отдельного поля не нужно). AEAD-тег рукопожатия (tag1,
// 16 байт) едет в session_id — поле, которое настоящий Chrome и так
// заполняет случайными 32 байтами для совместимости с middlebox'ами, так
// что по байтам неотличимо.
//
// ServerHello от сервера пока НЕ мимикрируется (см. README) — активный
// пробинг, доводящий handshake до конца, это всё ещё увидит.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	tls "github.com/refraction-networking/utls"
)

const maxMimicHelloLen = 8192

func buildMimicClientHello(sni string, ecPub, tag1 []byte) ([]byte, error) {
	uconn := tls.UClient(nil, &tls.Config{ServerName: sni}, tls.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uconn.HandshakeState.Hello

	found := false
	for i := range hello.KeyShares {
		if hello.KeyShares[i].Group == tls.X25519 {
			hello.KeyShares[i].Data = ecPub
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("mirage: chrome fingerprint has no x25519 key share")
	}

	sessionID := make([]byte, 32)
	copy(sessionID, tag1)
	if _, err := rand.Read(sessionID[len(tag1):]); err != nil {
		return nil, err
	}
	hello.SessionId = sessionID

	hello.Raw = nil // force re-marshal: Marshal() returns stale .Raw bytes otherwise
	body, err := hello.Marshal()
	if err != nil {
		return nil, err
	}

	record := make([]byte, 5+len(body))
	record[0] = 0x16                          // handshake content type
	record[1], record[2] = 0x03, 0x01         // legacy record version; real TLS1.3 clients send this too
	binary.BigEndian.PutUint16(record[3:5], uint16(len(body)))
	copy(record[5:], body)
	return record, nil
}

// parseMimicClientHello reads one mimicked ClientHello record from r.
// consumed always holds every byte actually read, even on error, so the
// caller's anti-probe fallback can replay exactly what a prober sent.
func parseMimicClientHello(r io.Reader) (ecPub, tag1, consumed []byte, err error) {
	hdr := make([]byte, 5)
	nHdr, hdrErr := io.ReadFull(r, hdr)
	consumed = append(consumed, hdr[:nHdr]...)
	if hdrErr != nil {
		return nil, nil, consumed, hdrErr
	}
	if hdr[0] != 0x16 {
		return nil, nil, consumed, errors.New("mirage: not a handshake record")
	}
	n := binary.BigEndian.Uint16(hdr[3:5])
	if n == 0 || n > maxMimicHelloLen {
		return nil, nil, consumed, errors.New("mirage: implausible client hello length")
	}
	body := make([]byte, n)
	nBody, bodyErr := io.ReadFull(r, body)
	consumed = append(consumed, body[:nBody]...)
	if bodyErr != nil {
		return nil, nil, consumed, bodyErr
	}

	hello := tls.UnmarshalClientHello(body)
	if hello == nil {
		return nil, nil, consumed, errors.New("mirage: not a valid client hello")
	}
	if len(hello.SessionId) < 16 {
		return nil, nil, consumed, errors.New("mirage: session id too short")
	}
	tag1 = hello.SessionId[:16]

	for _, ks := range hello.KeyShares {
		if ks.Group == tls.X25519 && len(ks.Data) == 32 {
			ecPub = ks.Data
			break
		}
	}
	if ecPub == nil {
		return nil, nil, consumed, errors.New("mirage: no x25519 key share")
	}
	return ecPub, tag1, consumed, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./... -run 'TestMimicClientHello|TestParseMimicClientHello' -v
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add camouflage.go camouflage_test.go
git commit -m "feat: build/parse mimicked Chrome ClientHello for msg1 camouflage"
```

---

### Task 3: Wire camouflage into the handshake

**Files:**
- Modify: `handshake.go:36-75` (`clientHandshake`)
- Modify: `handshake.go:78-119` (`serverHandshake`)

**Interfaces:**
- Consumes: `buildMimicClientHello(sni string, ecPub, tag1 []byte) ([]byte, error)` and `parseMimicClientHello(r io.Reader) (ecPub, tag1, consumed []byte, err error)` from Task 2.
- Produces: `clientHandshake(conn net.Conn, serverPub, psk []byte, sni string) (*secureConn, error)` — new signature (added `sni string`), consumed by Task 4.
- `serverHandshake`'s signature is unchanged: `serverHandshake(conn net.Conn, priv *ecdh.PrivateKey, psk []byte) (sc *secureConn, consumed []byte, err error)`.

- [ ] **Step 1: Update `clientHandshake` to send the mimicked ClientHello**

In `handshake.go`, change the function signature and the msg1 write. Replace:

```go
func clientHandshake(conn net.Conn, serverPub, psk []byte) (*secureConn, error) {
	ec, err := genKey()
	if err != nil {
		return nil, err
	}
	ecPub := ec.PublicKey().Bytes()

	es, err := ecdhShared(ec, serverPub)
	if err != nil {
		return nil, err
	}
	k1 := hkdfExpand(hkdfExtract(psk, es), labelHS, 32)
	a := newAEAD(k1)

	tag1 := a.Seal(nil, nonce12(0), nil, ecPub)
	if _, err := conn.Write(concat(ecPub, tag1)); err != nil {
		return nil, err
	}
```

with:

```go
func clientHandshake(conn net.Conn, serverPub, psk []byte, sni string) (*secureConn, error) {
	ec, err := genKey()
	if err != nil {
		return nil, err
	}
	ecPub := ec.PublicKey().Bytes()

	es, err := ecdhShared(ec, serverPub)
	if err != nil {
		return nil, err
	}
	k1 := hkdfExpand(hkdfExtract(psk, es), labelHS, 32)
	a := newAEAD(k1)

	tag1 := a.Seal(nil, nonce12(0), nil, ecPub)
	msg1, err := buildMimicClientHello(sni, ecPub, tag1)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg1); err != nil {
		return nil, err
	}
```

The rest of `clientHandshake` (reading msg2, deriving `master`/`kc2s`/`ks2c`) is unchanged.

- [ ] **Step 2: Update `serverHandshake` to parse the mimicked ClientHello**

Replace:

```go
func serverHandshake(conn net.Conn, priv *ecdh.PrivateKey, psk []byte) (sc *secureConn, consumed []byte, err error) {
	buf := make([]byte, hsMsgLen)
	n, rerr := io.ReadFull(conn, buf)
	consumed = buf[:n]
	if rerr != nil {
		return nil, consumed, rerr
	}
	ecPub, tag1 := buf[:32], buf[32:48]

	es, e := ecdhShared(priv, ecPub)
```

with:

```go
func serverHandshake(conn net.Conn, priv *ecdh.PrivateKey, psk []byte) (sc *secureConn, consumed []byte, err error) {
	ecPub, tag1, consumed, perr := parseMimicClientHello(conn)
	if perr != nil {
		return nil, consumed, perr
	}

	es, e := ecdhShared(priv, ecPub)
```

The rest of `serverHandshake` (AEAD open of tag1, generating `esKey`/tag2, writing msg2, deriving `master`/`kc2s`/`ks2c`) is unchanged.

- [ ] **Step 3: Update the file-level doc comment**

In `handshake.go`, replace the `Wire:` comment block (lines 11-15):

```go
// Wire:
//   msg1 (client->server): e_pub_c(32) || tag1(16)   tag1 = AEAD(k1, n=0, "", ad=e_pub_c)
//   msg2 (server->client): e_pub_s(32) || tag2(16)   tag2 = AEAD(k1, n=1, "", ad=e_pub_s)
//   k1 = HKDF( extract(PSK, es), "mirage-v0 hs" )
//   master = extract(PSK, es||ee); k_c2s/k_s2c = HKDF(master, label||e_pub_c||e_pub_s)
```

with:

```go
// Wire:
//   msg1 (client->server): mimicked TLS 1.3 ClientHello (Chrome fingerprint,
//     see camouflage.go) carrying e_pub_c in its key_share extension and
//     tag1 in its session_id.  tag1 = AEAD(k1, n=0, "", ad=e_pub_c)
//   msg2 (server->client): e_pub_s(32) || tag2(16)   tag2 = AEAD(k1, n=1, "", ad=e_pub_s)
//     (raw, not TLS-framed — see README "Что дальше" for the remaining gap)
//   k1 = HKDF( extract(PSK, es), "mirage-v0 hs" )
//   master = extract(PSK, es||ee); k_c2s/k_s2c = HKDF(master, label||e_pub_c||e_pub_s)
```

- [ ] **Step 4: Confirm the project compiles (tests will fail to compile until Task 4 updates the caller)**

```bash
go vet ./... 2>&1 | head -20
```

Expected: an error that `main.go` calls `clientHandshake` with the old 3-argument signature — this is expected and fixed in Task 4.

- [ ] **Step 5: Commit**

```bash
git add handshake.go
git commit -m "feat: send/parse msg1 as a mimicked ClientHello in the handshake"
```

---

### Task 4: Add `-sni` client flag and update the caller

**Files:**
- Modify: `main.go:144-196` (`cmdClient`, `clientConn`)

**Interfaces:**
- Consumes: `clientHandshake(conn net.Conn, serverPub, psk []byte, sni string) (*secureConn, error)` from Task 3.
- Produces: `clientConn(c net.Conn, server string, pub, psk []byte, sni string)` — new signature.

- [ ] **Step 1: Add the flag and thread it through**

Replace:

```go
func cmdClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listen")
	server := fs.String("server", "", "mirage server HOST:PORT")
	pubHex := fs.String("pub", "", "server public key (hex)")
	pskHex := fs.String("psk", "", "pre-shared key (hex)")
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
		go clientConn(c, *server, pub, psk)
	}
}

func clientConn(c net.Conn, server string, pub, psk []byte) {
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
	sc, err := clientHandshake(up, pub, psk)
	if err != nil {
		log.Printf("handshake: %v", err)
		up.Close()
		return
	}
	up.SetDeadline(time.Time{})
```

with:

```go
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
```

The rest of `clientConn` (writing `encodeAddr`, `relay(sc, c)`) is unchanged.

- [ ] **Step 2: Build and run the full test suite**

```bash
go build ./...
go test ./... -v
```

Expected: build succeeds, all tests (including Task 2's three) PASS.

- [ ] **Step 3: Commit**

```bash
git add main.go
git commit -m "feat: add -sni client flag, wire it through to the handshake"
```

---

### Task 5: Manual loopback verification

This mirrors the README's existing "Что проверено (loopback)" section — the
whole point of this feature is the anti-detection property, which a unit
test can't fully stand in for. Run this for real, once, against localhost.

**Files:** none (verification only).

Background processes here use explicit PID files (`echo $! > file.pid`), not
shell job control (`&` + `%1`) — job numbers don't survive across separate
tool invocations in this environment, PIDs in files do.

- [ ] **Step 1: Build the binary and generate keys**

```bash
export PATH=$HOME/sdk/go1.26.4/bin:$PATH
cd /home/dmitry/Desktop/mirage
go build -o mirage .
./mirage keygen
```

Note the printed `server_priv`, `server_pub`, `psk`.

- [ ] **Step 2: Start a local "target" HTTP server (what the tunnel should reach)**

```bash
python3 -m http.server 18080 --bind 127.0.0.1 > /tmp/mirage-verify-http.log 2>&1 &
echo $! > /tmp/mirage-verify-http.pid
```

- [ ] **Step 3: Start the mirage server** (fallback `dest` can point at the same test server, or any other local site)

```bash
./mirage server -listen 127.0.0.1:8443 -priv <PRIV> -psk <PSK> -dest 127.0.0.1:18080 > /tmp/mirage-verify-server.log 2>&1 &
echo $! > /tmp/mirage-verify-server.pid
```

- [ ] **Step 4: Start the mirage client**

```bash
./mirage client -listen 127.0.0.1:1080 -server 127.0.0.1:8443 -pub <PUB> -psk <PSK> > /tmp/mirage-verify-client.log 2>&1 &
echo $! > /tmp/mirage-verify-client.pid
```

- [ ] **Step 5: Verify legitimate traffic passes through the disguised handshake**

```bash
curl --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:18080/
```

Expected: HTTP directory listing from the Python server — confirms the full
build→write→parse→auth→tunnel path works end-to-end with the new
ClientHello framing.

- [ ] **Step 6: Verify a bad PSK is still rejected**

```bash
./mirage client -listen 127.0.0.1:1081 -server 127.0.0.1:8443 -pub <PUB> -psk 00112233445566778899001122334455 > /tmp/mirage-verify-badpsk.log 2>&1 &
echo $! > /tmp/mirage-verify-badpsk.pid
curl --socks5-hostname 127.0.0.1:1081 -m 5 http://127.0.0.1:18080/
```

Expected: curl times out / connection fails (handshake auth fails server-side, tunnel never opens).

- [ ] **Step 7: Verify raw probes still get transparently proxied to `dest`**

```bash
printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' | nc -q1 127.0.0.1 8443
```

Expected: an HTTP response from the Python server on port 18080 (the fallback
`dest`) — confirms `parseMimicClientHello`'s error path still hands
`fallback()` exactly the probe's bytes to replay, same as before this change.

- [ ] **Step 8: Clean up background processes**

```bash
kill "$(cat /tmp/mirage-verify-http.pid)" \
     "$(cat /tmp/mirage-verify-server.pid)" \
     "$(cat /tmp/mirage-verify-client.pid)" \
     "$(cat /tmp/mirage-verify-badpsk.pid)" 2>/dev/null
rm -f /tmp/mirage-verify-*.pid /tmp/mirage-verify-*.log
```

- [ ] **Step 9: Record the result**

No commit needed for this task (nothing changes in the repo) — just confirm
all three checks in Step 5/6/7 behaved as expected before moving to Task 6.

---

### Task 6: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the intro (remove the "stdlib only" claim)**

Replace:

```
Минимальный работающий PoC ядра: аутентифицированное рукопожатие X25519,
AEAD-фреймы, SOCKS5-вход, анти-зонд-fallback. Только stdlib Go, без
зависимостей.
```

with:

```
Минимальный работающий PoC ядра: аутентифицированное рукопожатие X25519,
AEAD-фреймы, SOCKS5-вход, анти-зонд-fallback, client->server рукопожатие
замаскировано под настоящий Chrome ClientHello (uTLS). Всё остальное —
stdlib; единственная внешняя зависимость — uTLS, нужна именно для
байт-в-байт совместимых TLS-фингерпринтов браузеров.
```

- [ ] **Step 2: Add a 4th verified bullet to "Что проверено (loopback)"**

After the existing 3 bullets, add:

```
4. Рукопожатие клиента замаскировано под TLS 1.3 ClientHello (Chrome) —
   первый байт на проводе больше не «голый» X25519.
```

- [ ] **Step 3: Add `camouflage.go` to the file list in "Как устроено"**

After the `handshake.go` line, add:

```
- `camouflage.go` — упаковка/разбор client->server рукопожатия как
  мимикрированного TLS ClientHello (uTLS, Chrome-фингерпринт)
```

- [ ] **Step 4: Update roadmap item 1**

Replace:

```
1. **uTLS-камуфляж + Reality-стиль.** Сейчас первый байт — «голый» X25519,
   энтропийный детектор его увидит. Оборачивать рукопожатие в настоящий
   TLS 1.3 ClientHello (JA4 браузера), auth смаглить в key_share. Это главное.
```

with:

```
1. **ServerHello-камуфляж (остаток Reality-стиля).** Client->server сторона
   уже мимикрирует под Chrome ClientHello (uTLS, см. camouflage.go).
   Server->client (msg2) всё ещё «голый» epub||tag2 — активный пробинг,
   доводящий handshake до конца, это заметит. Следующий шаг: либо
   статический ServerHello-шаблон со своим key_share, либо полноценный
   Reality (проксирование настоящего handshake для честного сертификата).
```

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: reflect ClientHello camouflage in README"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-06-clienthello-camouflage.md`.
