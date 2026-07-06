# ClientHello camouflage (uTLS) — design

## Problem

Roadmap item 1 (README, "Что дальше"): the handshake's first byte on the wire
is a bare X25519 public key + AEAD tag. An entropy/format-based DPI detector
can flag this immediately as non-TLS traffic, defeating the point of the
anti-probe fallback (which only protects against *active probing*, not
passive fingerprinting of the opening bytes).

## Scope

Client → server direction only. The server's response (msg2) stays exactly
as it is today: raw `epub || tag2`, no TLS framing. Making the server's
response also look like a TLS 1.3 ServerHello is deliberately deferred —
noted as a follow-up limitation below, not solved here.

## Design

Add `github.com/refraction-networking/utls` (latest: v1.8.2) as the project's
first non-stdlib dependency. This replaces the "only stdlib, no dependencies"
line in the README, which is updated to explain why.

### New file: `camouflage.go`

- `buildMimicClientHello(ecPub, tag1 []byte) ([]byte, error)`
  Builds a `ClientHelloMsg` using uTLS's `HelloChrome_Auto` fingerprint spec
  (real Chrome JA3/JA4 shape, GREASE randomized per-call like a real client).
  Patches two fields on the resulting struct before marshaling:
  - the X25519 `KeyShare` entry's data → `ecPub` (already the right shape:
    32 bytes, no new field needed)
  - `SessionId` → `tag1` (16 bytes) + random padding to fill 32 bytes
    (real Chrome sends a 32-byte random session ID for middlebox compat, so
    this is indistinguishable from that at the byte level)
  Returns the marshaled raw TLS record bytes.

- `parseMimicClientHello(r io.Reader) (ecPub, tag1, consumed []byte, err error)`
  Server-side counterpart: reads the TLS record header to learn the length,
  reads the handshake body, and extracts the KeyShare/SessionId fields the
  same way in reverse. **Always returns whatever bytes were read so far**,
  even on error — this is what the existing anti-probe fallback replays to
  `dest`. This contract must not regress.

### Changed: `handshake.go`

- `clientHandshake`: replace `conn.Write(concat(ecPub, tag1))` with
  `conn.Write(buildMimicClientHello(ecPub, tag1))`.
- `serverHandshake`: replace the fixed 48-byte `io.ReadFull` with
  `parseMimicClientHello(conn)`. Any parse or auth failure still returns
  `consumed` bytes unchanged, so `fallback()` in `main.go` keeps working
  exactly as before.
- msg2 (server's reply) is untouched.

## Error handling

Unchanged contract: anything that fails to parse as a valid mimicked
ClientHello, or fails PSK auth, falls through to `fallback()`, which replays
the consumed bytes to `dest` and transparently proxies the connection. This
is the one behavior that must survive the change — it's what makes the
server "look like" an ordinary web server to a prober.

## Testing

The repo currently has no test files. This change introduces the first
non-trivial parser in the project, so per the project's own testing bar it
gets one focused test file, `camouflage_test.go`:

1. Round-trip: `buildMimicClientHello` → `parseMimicClientHello` recovers the
   same `ecPub`/`tag1`.
2. Garbage input (random bytes, short reads) still yields a `consumed`
   byte slice and a non-nil error — i.e., the fallback path still has
   something to replay.

Pre-existing files are not retrofitted with tests — out of scope.

## Known limitation (not solved here)

Server's response (msg2) does not look like a TLS ServerHello. An active
prober that completes the TLS handshake (not just inspects the ClientHello)
can still notice the mismatch. Full Reality-style mimicry (server also
speaks a plausible ServerHello, or proxies the real handshake to borrow a
genuine certificate) is a larger follow-up, not this iteration.
