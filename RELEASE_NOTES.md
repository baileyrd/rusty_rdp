# Release Notes

The story of `rusty_rdp`, one wire format at a time. Newest first.

---

## Client-side TLS now runs on `rusty_tls`
**2026-07-21**

- **Changed:** `connect_tls()`/`connect_tls_with_csprng()` (and the Kerberos
  variants) now build their TLS connection through
  [`rusty_tls`](https://github.com/baileyrd/rusty_tls) — the rusty
  ecosystem's shared TLS implementation and trust policy — instead of this
  crate's own hand-built `AcceptAnyServerCert` verifier. Behavior is
  unchanged (still `TrustPolicy::DangerNoVerification`, i.e. no certificate
  verification, matching RDP's typical self-signed/out-of-band-trust
  deployment); what changed is who owns that decision and its name.
- **Added (to `rusty_tls`, consumed here):** `TlsStream::complete_handshake()`
  and `TlsStream::peer_certificate_der()` — this crate's CredSSP exchange
  needs the server's public key for channel binding before the CredSSP
  bytes go over the wire, which previously meant reaching directly into
  `rustls::StreamOwned`'s internals. These two methods are the minimal
  surface that removes that.
- **Unchanged:** server-side TLS (`accept_tls`/`accept_tls_nla`,
  `TlsServerStream`) — `rusty_tls` has no server-side support yet, so that
  half of `tls.rs` still builds directly on `rustls`.
- **Known limitation, stated plainly:** no way yet to opt a client connector
  into real certificate verification without hand-writing your own TLS
  stream and calling `RdpTransport::new_enhanced` directly — see the module
  docs' Certificate verification section.
- **Tests:** all 541 existing tests pass unmodified (543 with the `platform`
  feature), including the full NTLM and Kerberos CredSSP/NLA flows that
  exercise the new channel-binding path end to end. `cargo clippy
  --all-targets --all-features -- -D warnings` and `cargo fmt --check` both
  clean.

## 0.1.0 — The Foundation Release

*A dependency-free RDP codec that speaks the full connection sequence, both
directions, over standard security, TLS, and CredSSP/NLA — with NTLM or
Kerberos.*

This is the first real release: everything below shipped as one continuous
build-out, from the raw TPKT framing at the bottom of the stack up through a
graphics pipeline that decodes RemoteFX, Planar, and ClearCodec straight to
pixels, and a security story that covers standard RC4/RSA, TLS, and
CredSSP/NLA on **both** the client and server side. Zero third-party
dependencies in the default build — the one exception, `rustls`, lives behind
an opt-in `tls` feature and nowhere else.

### 🔐 Security & authentication

- **Standard RDP security**, client and server: the RSA key exchange, the
  session-key derivation schedule, and RC4 + MAC framing for encrypted PDUs.
  The server side signs its certificate with the fixed, publicly-documented
  `ts_signing_key` — the same trick every RDP server has used since Windows
  2000.
- **TLS**, client and server: `connect_tls()` upgrades the wire and drives the
  enhanced-security handshake; `accept_tls()` is the server-side mirror,
  negotiating `SSL` and accepting a caller-supplied `rustls::ServerConfig`.
- **CredSSP / NLA**, client and server, **NTLM or Kerberos**:
  - `NtlmClient`/`NtlmServer` drive full NTLMv2 NEGOTIATE → CHALLENGE →
    AUTHENTICATE in both directions, verified against the published MS-NLMP
    test vectors. The server side checks a client's password via a
    caller-supplied hash callback — this crate never stores or looks up
    credentials itself.
  - `CredSspClient`/`CredSspServer` drive the three-leg `TSRequest` exchange,
    the public-key channel binding (SHA-256 nonce hash for CredSSP 5+, the
    legacy scheme otherwise), and sealed credential delegation.
  - A full **Kerberos KDC client** (`krb5::kdc`) means Kerberos auth needs
    nothing but a realm, username, and password — no external `kinit`, no
    keytab. `fetch_ap_req` drives both KDC round trips (AS then TGS) over
    real TCP and hands back exactly the `(ap_req_bytes, session_key)` pair
    `connect_tls_kerberos` takes.
  - `accept_tls_nla` wires NTLM-based CredSSP into a live server accept end
    to end, including the "wrong password" rejection path. (Kerberos stays
    client-only — validating an `AP-REQ` server-side needs a keytab, a much
    bigger undertaking than everything else here.)
- **A real bug, caught by testing it properly:** `Rc4Session::new` derives
  keys from the *client's* point of view. A server calling it directly on the
  same session keys silently got its encrypt/decrypt roles backwards — invisible
  until the first test that ran two independently-built peers against each
  other for real. `Rc4Session::new_server` now does the correct swap, and the
  same client/server split now runs through `NtlmContext` and Kerberos AP-REQ
  handling too.

### 🖥️ Server side

`RdpTransport::accept` drives the entire server half of the connection
sequence — negotiation, GCC/MCS connect, channel setup, logon, licensing,
capability exchange, finalization — over the same bidirectional codec types
the client path uses. It speaks:

- Unencrypted standard security (the default)
- Encrypted standard security (RSA + RC4)
- TLS (`accept_tls`)
- TLS + CredSSP/NLA (`accept_tls_nla`)

Every path is tested end to end over a real TCP loopback against this crate's
own client — `establish()` or `connect_tls()` on one side, `accept()` on the
other, actually talking to each other.

### 🎨 Graphics pipeline

The full MS-RDPEGFX (RDPGFX) surface, and every bitmap codec it carries:

- **RemoteFX** (`rfx`) — RLGR1/RLGR3 entropy decoding, the 3-level 5/3
  lifting-scheme inverse DWT, dequantization, and YCbCr→RGB.
- **Planar** (`planar`) — RDP 6.0's scan-line delta RLE scheme, AYCoCg with
  color-loss reduction and 2×2 chroma subsampling.
- **ClearCodec** (`clearcodec`) — residual/bands/subcodec compositing, plus
  the persistent glyph and VBar caches later frames reference by index.
- **AVC420/AVC444** (`gfx`) — region and quantization metadata parsed and
  handed back with the raw H.264 bitstream untouched (decoding H.264 itself
  needs a real decoder — out of scope for a dependency-free crate).
- Surface lifecycle, bitmap caching, composition, and output mapping — the
  PDUs that make the codecs above actually land on screen.

### 📋 Channels

- **Clipboard** (`cliprdr`, MS-RDPECLIP) — format negotiation, text transfer,
  and file copy/paste (`FileList`, `FileContentsRequestPdu`/`ResponsePdu`,
  clip-data locking).
- **Audio** (`rdpsnd`, MS-RDPEA) — format negotiation, bandwidth training,
  both wave formats (the legacy WaveInfo/Wave split and the newer single-PDU
  `Wave2Pdu`), volume/pitch control, and encryption key distribution.
- **Device redirection** (`rdpdr`, MS-RDPEFS) — the full init/capability
  handshake and Device I/O Request/Response exchange: create/close/read/write,
  the generic IOCTL/FSCTL carrier smartcard and port redirection ride on,
  file/volume information, and directory listing/change notification.

### 🧱 The foundation underneath all of it

TPKT framing, X.224, RDP security-protocol negotiation, MCS, GCC (with hand-rolled
BER and ALIGNED-PER codecs), the Share Control/Data PDU framing every session
PDU rides in, capability exchange, finalization, fast-path input/output
framing, interleaved RLE bitmap decompression, native pixel-format unpacking,
and a hand-rolled crypto layer (MD4, MD5, SHA-1, SHA-256, HMAC, RC4, AES,
PBKDF2, and a minimal RSA bignum) — no crypto crate, anywhere, for any of it.

### Known gaps

- **USB redirection** (MS-RDPEUSB) isn't implemented — a substantially larger
  protocol than anything above, with its own dynamic channel and USB Request
  Block framing.
- **Smartcard/printer protocols** (MS-RDPESC, MS-RDPEPC) aren't modeled above
  the generic RDPDR IOCTL carrier they ride on — a caller gets raw IOCTL
  bytes today.
- **RDPDR lock control** isn't implemented — its wire layout was never
  published, and no reference client parses it either.
- **Kerberos server-side validation** needs a keytab and is out of scope for
  now.
- Encoding (the server-to-client direction) for RemoteFX/Planar/ClearCodec,
  and originating display updates / consuming input from a real server
  application, are both future work — `accept()` and friends drive the
  *connection sequence*, not a full server.

---

*Have thoughts on what should come next? Open an issue.*
