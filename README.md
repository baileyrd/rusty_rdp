# rusty_rdp

[![Release](https://img.shields.io/github/v/release/baileyrd/rusty_rdp?label=release)](https://github.com/baileyrd/rusty_rdp/releases/latest)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust: 1.70+](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](#building)

A minimal, **dependency-free** implementation of the Remote Desktop Protocol
(RDP) wire format in Rust.

The goal is a clean RDP codec built on nothing but the Rust standard library —
no `tokio`, no `openssl`, no third-party crates in the core at all. Every wire
structure is encoded and decoded by hand with bounds-checked cursors, and
`unsafe` is forbidden crate-wide.

## Status

🎉 **[v0.1.0 — "The Foundation Release"](https://github.com/baileyrd/rusty_rdp/releases/tag/v0.1.0) is out.**

Broad protocol coverage, built bottom-up and still growing. The full client
connection sequence (standard security, TLS, CredSSP/NLA with either NTLM or
Kerberos), the server side of that same sequence (including NLA), the RDPGFX
graphics pipeline with every bitmap codec it carries, and the clipboard/audio/
device-redirection channels are all implemented and tested. See
[Roadmap](#roadmap) below for what's left, and
[RELEASE_NOTES.md](RELEASE_NOTES.md) for the full writeup.

Layer by layer:

| Layer | Module | What it does |
|-------|--------|--------------|
| TPKT (RFC 1006) | `tpkt` | 4-byte length framing over TCP, with stream-friendly `peek_total_len`. |
| X.224 Class 0 | `x224` | Connection Request / Confirm / Data TPDUs, cookie parsing. |
| RDP negotiation | `nego` | `RDP_NEG_REQ` / `RSP` / `FAILURE` security selection. |
| MCS (T.125) | `mcs` | `Connect-Initial` / `Connect-Response` and the domain PDUs (erect domain, attach user, channel join, send data). |
| GCC (T.124) | `gcc` | Conference Create Request/Response envelope and the typed `TS_UD_*` settings blocks (client/server core, security, network, cluster). |
| Standard security | `security` | Server certificate → RSA key, client-random encryption, the key-derivation schedule, the Security Exchange PDU, the basic security header, and RC4 + MAC for encrypted PDUs. The server side of the RSA exchange is implemented too — `RsaPrivateKey` decryption and `encode_proprietary_certificate` (signed with the fixed, publicly-known `ts_signing_key`) — and wired into `net`'s `accept()`. `Rc4Session::new`/`new_server` build the RC4 state for each end of the exchange from the same `SessionKeys`, applying the client/server encrypt-decrypt role swap `SessionKeys`'s fields are documented from the client's point of view. |
| Crypto primitives | `crypto` | Hand-rolled MD4, MD5, SHA-1, SHA-256, HMAC-MD5/SHA-1, RC4, AES, PBKDF2, and a minimal bignum for RSA — no crypto crate. |
| NTLM | `ntlm` | NTLMv2 authentication (MS-NLMP), both roles: `NtlmClient` (NEGOTIATE/AUTHENTICATE) and `NtlmServer` (CHALLENGE, then verifies AUTHENTICATE against a caller-supplied password-hash callback), the NTLMv2 response and key schedule, and the extended-session-security sealing (`NtlmContext`, `new`/`new_server` for the two roles) used by CredSSP. |
| CredSSP / NLA | `credssp` | The `TSRequest` DER exchange (MS-CSSP): `CredSspClient` (NTLM and Kerberos) and `CredSspServer` (NTLM only), the public-key channel binding (SHA-256 nonce hash, or legacy), and sealed credential delegation (`decode_ts_credentials` recovers what the server delegates to). Pure codec + crypto, driven over TLS by the `tls` feature. |
| Kerberos | `krb5` | Kerberos v5 (RFC 4120 / MS-KILE): the RC4-HMAC (etype 23) and AES (etypes 17/18, RFC 3962) encryption profiles, the ASN.1 building blocks, the message PDUs (`Ticket`, `Authenticator`, `AP-REQ`, the AS/TGS exchange, `KRB-ERROR`), the GSS-API/SPNEGO wrapping (`krb5::gss`) that carries the AP-REQ in CredSSP `negoTokens`, the RFC 4121 per-message Wrap/MIC sealing (`krb5::cfx`), and a full KDC client (`krb5::kdc`) over TCP — `get_tgt` (AS exchange, with optimistic `PA-ENC-TIMESTAMP` pre-authentication), `tgs_exchange` (TGS exchange), `build_ap_req`, and `fetch_ap_req`, which chains all three to go straight from a realm/username/password/service-principal to the `(ap_req_bytes, session_key)` pair `connect_tls_kerberos` takes. Client-side only — there is no Kerberos-accepting server (validating an `AP-REQ` needs a keytab). |
| Client Info | `client_info` | `TS_INFO_PACKET` logon data (domain/user/password/shell, extended info). |
| Licensing | `license` | Licensing preamble and the License Error Message (`STATUS_VALID_CLIENT` detection). |
| Session framing | `pdu` | Share Control / Share Data headers with the `PDUTYPE` / `PDUTYPE2` constants. |
| Capabilities | `capabilities` | Demand Active / Confirm Active PDUs and the core capability sets (general, bitmap, pointer, input, share; others preserved raw). |
| Finalization | `finalization` | Synchronize / Control / Font List / Font Map PDUs and the client finalization sequence. |
| Input | `input` | Client Input Event PDU with scancode / Unicode / mouse / extended-mouse / sync events. |
| Output | `output` | Server graphics Update PDUs: bitmap (rectangles + verbatim data stream), palette, synchronize; orders kept raw. |
| Pointer | `pointer` | Server cursor updates: system / position / color / new / cached, with `ColorPointer::to_rgba()` for cursor rendering. |
| Fast-path | `fastpath` | The compact framing servers use for most traffic: output update parsing (bitmap/palette/pointer) and tight input event encoding. |
| Bitmap RLE | `rle` | The interleaved RLE bitmap decompressor (8/15/16/24 bpp), reachable via `BitmapData::decompressed()`. |
| Pixel unpack | `pixel` | Native pixel formats (8 indexed / 15 / 16 / 24 / 32 bpp) → top-down RGBA8888, via `BitmapData::to_rgba()`. |
| Framebuffer | `display` | RGBA desktop surface with clipped blit, `apply_bitmap`, and a PPM dump; assembles server bitmap updates. |
| TCP driver | `net` | Blocking `RdpTransport<S>` with `establish()` — the full standard-RDP bring-up (negotiation → MCS → security → logon → licensing → capabilities → finalization) — plus `establish_enhanced()` for the TLS path, `accept()` for the server side (see below), the individual steps, secure I/O-channel send/recv, and generic static-virtual-channel routing (`extra_channels`, `RdpEvent::ChannelData`, `send_channel_data`). The one module that touches a socket. |
| Virtual channel chunking | `vchan` | MS-RDPBCGR 2.2.6.1 `CHANNEL_PDU_HEADER` framing shared by every static virtual channel: splits outbound messages into chunks and reassembles inbound ones. What `net` uses to receive traffic on any channel beyond the I/O channel. |
| Dynamic virtual channels | `dvc` | MS-RDPEDYC PDU framing for the `DRDYNVC` channel that RDPGFX, clipboard, and other redirection protocols multiplex over: create/data/close, the version 1–3 capability exchange, and `fragment()` for outbound message splitting. |
| DVC session management | `dvcman` | `DvcManager` — tracks open dynamic channels, auto-accepts `Create` requests and echoes `Capabilities` requests, and reassembles a channel's own fragmented messages into `DvcEvent::{ChannelOpened, Data, ChannelClosed}`. The layer a caller drives with `net`'s `RdpEvent::ChannelData` to reach a named DVC-based protocol (e.g. RDPGFX) without hand-parsing `dvc` PDUs. |
| Graphics pipeline | `gfx` | MS-RDPEGFX PDUs carried over the `dvc`/`dvcman` `"Microsoft::Windows::RDS::Graphics"` channel: capability negotiation (`CapsAdvertisePdu`/`CapsConfirmPdu`), surface lifecycle (`CreateSurfacePdu`/`DeleteSurfacePdu`), the bitmap-carrying and frame-sequencing PDUs (`WireToSurface1Pdu`/`WireToSurface2Pdu`, `StartFramePdu`/`EndFramePdu`/`FrameAcknowledgePdu`), the bitmap cache PDUs (`SurfaceToCachePdu`/`CacheToSurfacePdu`/`EvictCacheEntryPdu`/`CacheImportOfferPdu`/`CacheImportReplyPdu`), surface composition (`SolidFillPdu`/`SurfaceToSurfacePdu`), output mapping (`ResetGraphicsPdu`, `MapSurfaceToOutputPdu`/`MapSurfaceToScaledOutputPdu`, `MapSurfaceToWindowPdu`/`MapSurfaceToScaledWindowPdu`), and the AVC420/AVC444 wrapper formats (`Avc420BitmapStream`/`Avc444BitmapStream`) — region and quantization metadata only, since decoding the H.264 bitstreams they carry needs an actual H.264 decoder. |
| RemoteFX codec | `rfx` | MS-RDPRFX tile decode for `gfx`'s `CODECID_CAVIDEO` bitmap data: RLGR1 and RLGR3 entropy decoding (`EntropyAlgorithm`), the 3-level 5/3 lifting-scheme inverse DWT, per-sub-band dequantization, and YCbCr→RGB, wired together by `Tile::decode_rgb`/`TileSet`, plus the control PDUs that wrap a tile set on the wire (`SyncPdu`, `CodecVersionsPdu`, `ChannelsPdu`, `ContextPdu`, `RegionPdu`, `FrameBeginPdu`/`FrameEndPdu`, dispatched by `peek_block_type`). The GFX cache/composition PDUs (`SURFACETOCACHE`, `SOLIDFILL`, etc.) belong to `gfx` instead, and encoding (the server-side direction) is not implemented. |
| Planar codec | `planar` | MS-RDPEGDI RDP 6.0 bitmap decode for `gfx`'s `CODECID_PLANAR` bitmap data: `decode()` turns an `RDP6_BITMAP_STREAM` into a top-down RGBA8888 buffer, handling all four color planes (alpha/luma-or-red/orange-or-green/green-or-blue), the scan-line delta RLE scheme (`RDP6_RLE_SEGMENT`), the optional AYCoCg color space with color-loss reduction and 2×2 chroma subsampling, and the documented decoder-side R/B swap. Decode-only, like `rfx`. |
| ClearCodec | `clearcodec` | MS-RDPEGFX decode for `gfx`'s `CODECID_CLEARCODEC` bitmap data: `ClearCodecDecoder` composites a `CLEARCODEC_BITMAP_STREAM`'s three payloads (a full-canvas run-length `residualData` fill, per-column `bandsData` "VBar" runs, and independent raw/RLEX `subcodecsData` sub-tiles) onto a top-down RGBA8888 buffer, and owns the persistent glyph and VBar/short-VBar caches later messages in the same session reference by index. NSCodec sub-tiles (`subcodecId == 1`) are not implemented. Decode-only, like `rfx`/`planar`. |
| Clipboard redirection | `cliprdr` | MS-RDPECLIP PDUs on the `"cliprdr"` static channel: the caps/monitor-ready handshake (`CapsPdu`/`GeneralCapabilitySet`/`MonitorReadyPdu`), format announcement (`FormatListPdu`/`FormatListResponsePdu`, Long Format Name variant), data transfer (`FormatDataRequestPdu`/`FormatDataResponsePdu`, with `as_unicode_text()` for `CF_UNICODETEXT`), and file copy/paste (`FileList`/`FileDescriptor` for the `CFSTR_FILEDESCRIPTORW` format, `FileContentsRequestPdu`/`FileContentsResponsePdu` to pull a file's size or byte ranges, `LockClipDataPdu`/`UnlockClipDataPdu`). `CB_TEMP_DIRECTORY` and the Short Format Name variant are not implemented. |
| Audio redirection | `rdpsnd` | MS-RDPEA PDUs on the `"rdpsnd"` static channel: format negotiation (`AudioFormatsPdu`/`AudioFormat`), bandwidth training (`TrainingPdu`/`TrainingConfirmPdu`), wave playback — both the legacy WaveInfo/Wave PDU split (`encode_wave`/`decode_wave` hide the split) and the newer single-PDU `Wave2Pdu` (`SNDC_WAVE2`, used once both sides negotiate version 8+) — `WaveConfirmPdu`, `ClosePdu`, volume/pitch control (`VolumePdu`/`PitchPdu`), and encryption key distribution (`CryptKeyPdu`). Everything that rides over UDP instead of this channel (encrypted wave data, the UDP wave PDUs) is not implemented. |
| Device redirection | `rdpdr` | MS-RDPEFS PDUs on the `"rdpdr"` static channel: the full initialization/capability handshake (`ServerAnnounceRequestPdu`/`ClientAnnounceReplyPdu`/`ServerClientIdConfirmPdu`/`ClientNameRequestPdu`, `ServerCoreCapabilityPdu`/`ClientCoreCapabilityPdu` with `GeneralCapsSet`, `ClientDeviceListAnnouncePdu`/`ServerDeviceAnnounceResponsePdu`, `ServerUserLoggedOnPdu`), and the full Device I/O Request/Response exchange (`DeviceIoRequest`/`DeviceIoResponse` headers) for every major function but one: create/close/read/write (`DeviceCreateRequestPdu`/`RspPdu`, `DeviceCloseRequestPdu`/`RspPdu`, `DeviceReadRequestPdu`/`RspPdu`, `DeviceWriteRequestPdu`/`RspPdu`), the generic IOCTL/FSCTL carrier (`DeviceControlRequestPdu`/`RspPdu`) that smart-card and port redirection ride on, query/set file information (`QueryInformationRequestPdu`/`RspPdu`, `SetInformationRequestPdu`/`RspPdu`), query/set volume information (`QueryVolumeInformationRequestPdu`/`RspPdu`, `SetVolumeInformationRequestPdu`/`RspPdu`), and directory control — listing (`QueryDirectoryRequestPdu`/`RspPdu`) and change notification (`NotifyChangeDirectoryRequestPdu`/`RspPdu`). Lock control is not implemented — its request layout isn't in Microsoft's published spec pages, and no reference client (FreeRDP, rdesktop, xrdp) actually parses it either. |
| TLS connector | `tls` | *(optional `tls` feature)* `connect_tls()` — upgrades the TCP stream to TLS with [`rusty_tls`](https://github.com/baileyrd/rusty_tls) (the rusty ecosystem's shared TLS implementation and trust policy) and drives `establish_enhanced()`; `accept_tls()`/`accept_tls_nla()` are the server-side counterparts, negotiating `SSL`/`HYBRID` respectively and driving `RdpTransport::accept`'s shared post-negotiation logic over a caller-supplied `rustls::ServerConfig` directly (`rusty_tls` has no server-side support yet) (`accept_tls_nla` also runs `CredSspServer` first, and returns the delegated `NlaIdentity`). The crate's only third-party dependencies, and off by default. |
| BER (X.690) | `ber` | The definite-length TLV subset the MCS connection PDUs need. |
| PER (X.691) | `per` | The ALIGNED-PER subset the MCS domain PDUs and GCC envelope need. |
| Byte cursors | `cursor` | Explicit big/little-endian, bounds-checked read/write. |

This is enough to build and parse the RDP connection sequence from the X.224
negotiation all the way through the logon and licensing exchange: the BER
`Connect-Initial`/`Response`, the GCC conference settings blocks, the PER
domain PDUs, the RSA/RC4 security handshake, the encrypted Client Info PDU, and
the licensing round trip, the Share Control / Share Data framing that every
session PDU rides in, the capability exchange (Demand / Confirm Active), the
connection-finalization sequence (synchronize, control, font list/map), and
client input events (keyboard and mouse), and the server-to-client display
path all the way to pixels: bitmap and palette updates, RLE decompression, and
pixel-format unpacking to a top-down RGBA framebuffer. Pointer/cursor updates
and fast-path framing build on top without disturbing what is here.

The enhanced-security (TLS) path is also wired up: `RdpTransport::negotiate()`
selects `SSL` on the raw TCP connection, the stream is upgraded to TLS, and
`RdpTransport::establish_enhanced()` drives MCS/GCC, logon, licensing,
capabilities and finalization inside the tunnel with the RDP security layer
switched off (no Security Exchange, no RC4 — TLS carries confidentiality). The
protocol logic for this lives entirely in the dependency-free core; the actual
TLS bytes are the one thing behind an optional feature.

CredSSP / NLA (the `HYBRID` path) is implemented too: NTLMv2 authentication,
the CredSSP `TSRequest` exchange with the public-key channel binding, and
sealed credential delegation — all in the dependency-free core (`ntlm`,
`credssp`), verified against the published MS-NLMP test vectors. With the `tls`
feature, `connect_tls()` runs the whole exchange over the TLS channel when the
server selects `HYBRID`. Both authentication mechanisms are wired end to end:
NTLMv2 (`connect_tls`) and Kerberos (`connect_tls_kerberos`, which takes a
ticket + AES session key and drives the SPNEGO/AP-REQ exchange sealed with
RFC 4121 Wrap tokens). Getting that ticket no longer needs an external
`kinit` or keytab: `krb5::kdc::fetch_ap_req` drives both KDC round trips (the
AS exchange for a Ticket-Granting Ticket, then the TGS exchange for the
actual service ticket) over real TCP connections to a KDC and assembles the
AP-REQ, going straight from a realm/username/password/service-principal to
the exact `(ap_req_bytes, session_key)` pair `connect_tls_kerberos` takes.

> **Security note:** the `crypto` and `security` modules implement obsolete,
> deliberately weak algorithms (RC4, MD5/SHA-1 MACs, unpadded RSA) purely to
> speak RDP *standard security*. They are not for general use; modern
> deployments should negotiate TLS/CredSSP. The `tls` feature's `connect_tls()`
> uses `rusty_tls::TrustPolicy::DangerNoVerification` — it does **not** verify
> the server certificate (RDP servers are typically self-signed with
> out-of-band trust), so it does not defend against an active
> man-in-the-middle — bring your own verified TLS stream (e.g. `rusty_tls`
> with `TrustPolicy::System`/`PinnedAnchors`) and use `establish_enhanced()`
> if you need that.

## Roadmap

Known gaps versus full-featured implementations (FreeRDP, IronRDP), roughly in
the order they'd add the most value:

- ~~**RemoteFX / GFX codec support.**~~ Done. The channel plumbing (`vchan`,
  `dvc`, `dvcman`), the MS-RDPEGFX capability negotiation, surface/frame
  PDUs, the bitmap cache PDUs (`SurfaceToCachePdu`/`CacheToSurfacePdu`/
  `EvictCacheEntryPdu`/`CacheImportOfferPdu`/`CacheImportReplyPdu`), surface
  composition (`SolidFillPdu`/`SurfaceToSurfacePdu`), and output mapping
  (`ResetGraphicsPdu`, `MapSurfaceToOutputPdu`/`MapSurfaceToScaledOutputPdu`,
  `MapSurfaceToWindowPdu`/`MapSurfaceToScaledWindowPdu`) are all wired up in
  `gfx`. Every bitmap codec RDPGFX carries is now handled: the RemoteFX
  tile codec (`rfx` — RLGR1/RLGR3 entropy decoding, the 3-level 5/3 inverse
  DWT, dequantization, and YCbCr→RGB, plus its control PDUs), the RDP 6.0
  Planar codec (`planar` — scan-line delta RLE, AYCoCg with color-loss
  reduction and chroma subsampling), and ClearCodec (`clearcodec` —
  residual/bands/subcodec compositing plus the persistent glyph and VBar
  caches it depends on, except its NSCodec sub-tile variant, a whole
  separate legacy codec out of scope on its own) all decode straight to
  pixels. AVC420/AVC444 (`gfx::Avc420BitmapStream`/`Avc444BitmapStream`)
  parse their region/quantization metadata and hand back the raw H.264
  Annex B bitstream unopened — actually decoding it needs a real H.264
  decoder, permanently out of scope for a dependency-free crate.
- **Channels: drive, USB, smartcard, and printer redirection.** The
  static/dynamic virtual channel plumbing all of these ride on (`vchan`,
  `dvc`, `dvcman`, and `net`'s generic channel routing) is implemented end
  to end, and clipboard redirection (CLIPRDR, `cliprdr`), audio redirection
  (RDPEA, `rdpsnd`), and RDPDR (`rdpdr`) are now implemented, essentially
  completely: the initialization/capability handshake and the full Device
  I/O Request/Response exchange — create/close/read/write, generic device
  control (the IOCTL/FSCTL carrier smart-card and port redirection ride on
  almost entirely), query/set file and volume information, and directory
  listing/change notification, plus, for `cliprdr`, file copy/paste
  (`FileList`/`FileDescriptor`, `FileContentsRequestPdu`/
  `FileContentsResponsePdu`, `LockClipDataPdu`/`UnlockClipDataPdu`), and
  for `rdpsnd`, volume/pitch control (`VolumePdu`/`PitchPdu`), encryption
  key distribution (`CryptKeyPdu`), and the newer single-PDU wave format
  (`Wave2Pdu`, `SNDC_WAVE2`, sent instead of the legacy WaveInfo/Wave pair
  once both sides negotiate version 8+). Still needed: RDPDR's lock control
  (its request layout isn't published anywhere findable, and no reference
  client implementation actually parses it either — low priority given
  that), and everything on either channel that rides over UDP instead of
  the virtual channel (encrypted wave audio, the UDP wave PDUs). Smartcard
  and printer/port redirection ride on RDPDR's generic IOCTL/FSCTL carrier
  (`DeviceControlRequestPdu`/`RspPdu`) and so already work at the framing
  level, but their own higher-level protocols (MS-RDPESC smartcard PC/SC
  calls, MS-RDPEPC print job control) aren't modeled — a caller gets the
  raw IOCTL bytes and has to interpret them itself. USB redirection
  (MS-RDPEUSB) is unrelated to RDPDR — its own dynamic channel (`URBDRC`)
  and USB Request Block framing — and is not implemented at all; it is a
  substantially larger protocol than anything else on this list.
- **Server-side RDP.** `RdpTransport::accept` drives the server half of the
  connection sequence — X.224 Connection Confirm, GCC/MCS Connect-Response,
  channel setup, Client Info, "no license required", Demand Active/Confirm
  Active, and the server's finalization sequence — reusing the same
  bidirectional codec types `establish*` uses. It supports both
  **unencrypted** standard RDP security (`encryptionLevel = 0`, the
  default) and, with `AcceptConfig::encryption` set, **real encrypted**
  standard security: the RSA key exchange, a certificate signed with the
  fixed `security::ts_signing_key`, and RC4. Tested end to end over a real
  TCP loopback connection — the unencrypted path against a hand-driven
  client (`establish` can't speak to an unencrypted server), the encrypted
  path against the real `RdpTransport::establish`. That encrypted test also
  caught a real bug: `Rc4Session::new` derives keys from the *client's*
  point of view, so a server using it directly on the same `SessionKeys`
  gets its encrypt/decrypt roles backwards; `Rc4Session::new_server` now
  does the correct swap.

  *(optional `tls` feature)* `tls::accept_tls` is the TLS-upgrading
  counterpart: it negotiates `SecurityProtocols::SSL` on the raw TCP stream
  (rejecting, with an `RDP_NEG_FAILURE`, a client that didn't offer it),
  upgrades using a caller-supplied `rustls::ServerConfig` (certificate +
  private key — this crate doesn't generate X.509 certificates, matching how
  `connect_tls` doesn't verify them), and then shares `accept`'s
  post-negotiation logic unchanged: every session-conditional framing helper
  already does the right thing under TLS, since `RdpTransport::session` stays
  `None` there (TLS supplies confidentiality instead of RC4). Tested end to
  end against the real `tls::connect_tls`, with a throwaway self-signed P-256
  test certificate.

  The NTLM/CredSSP *authentication* primitives a `HYBRID`-accepting server
  needs also exist: `ntlm::NtlmServer` builds the CHALLENGE and verifies a
  client's AUTHENTICATE (NTProofStr and MIC) against a caller-supplied
  password-hash callback — this crate never stores or looks up credentials
  itself — and `credssp::CredSspServer` drives the three-leg `TSRequest`
  exchange on top of it, ending with the delegated `(domain, user,
  password)` decoded from `authInfo`.

  `tls::accept_tls_nla` wires all of that into a live connection: it
  negotiates `SecurityProtocols::HYBRID` (rejecting a client that didn't
  offer it), upgrades to TLS, drives `CredSspServer`'s three legs over the
  TLS stream (replying with a `STATUS_LOGON_FAILURE` `TSRequest` on
  authentication failure), then shares `accept`'s post-negotiation logic
  like `accept_tls` does, returning the delegated identity as
  `tls::NlaIdentity` alongside the accepted client. `tls::extract_spki` is
  exposed publicly so a caller can pull the `public_key` `CredSspServer::new`
  needs from the same certificate DER used to build the `rustls::ServerConfig`.
  Tested end to end against the real `tls::connect_tls`, including
  wrong-password rejection and a client that never offered `HYBRID`.
  Kerberos is not supported server-side (validating an `AP-REQ` needs a
  keytab and a much larger surface), and `HYBRID_EX`'s Early User
  Authorization Result PDU is not sent — only the base `HYBRID` protocol.

  Beyond the connection sequence, an actual server also needs to originate
  display updates and consume input, which `accept`/`accept_tls`/
  `accept_tls_nla` do not attempt.

## Design principles

- **No I/O in the codec.** The codec types encode to and decode from byte
  slices, so the same code works with blocking sockets, any async runtime, or
  in-memory tests. Socket access lives in exactly one module (`net`), a thin
  blocking driver kept apart from the codec.
- **Minimal dependencies.** The core has zero. The one thing that genuinely
  needs a third-party crate — a TLS stack, which cannot be hand-rolled
  responsibly — lives behind the optional `tls` feature (`rustls` for the
  server side, `rusty_tls` for the client connectors), never in the default
  build. Even the RDP-over-TLS *protocol* logic stays in the
  dependency-free core: the transport is generic over the stream, so you can
  bring your own TLS implementation instead. RSA for standard RDP security is
  hand-rolled, so it needs no crate.
- **Total decoding.** Malformed input returns an `Error`; it never panics.
- **Explicit endianness.** RDP mixes big-endian transport framing with
  little-endian RDP structures, so every integer access names its byte order.

## Example

```rust
use rusty_rdp::nego::{Negotiation, SecurityProtocols};
use rusty_rdp::tpkt::Tpkt;
use rusty_rdp::x224::X224;

// Client Connection Request asking for TLS or CredSSP.
let neg = Negotiation::Request {
    flags: 0,
    protocols: SecurityProtocols::SSL | SecurityProtocols::HYBRID,
};
let x224 = X224::connection_request(neg);
let tpdu = x224.to_vec().unwrap();
let packet = Tpkt::new(&tpdu).to_vec().unwrap();
// `packet` is ready to write to a TCP socket.
```

## Building

```sh
cargo build            # zero dependencies
cargo test
cargo build --features tls        # opt-in TLS connector (pulls in rustls + rusty_tls)
cargo build --features platform   # opt-in platform::net::TcpStream adapter
cargo build --features serve-example   # opt-in `serve` example (Sandbox confinement)
```

The default build has no dependencies and keeps an MSRV of 1.70. The optional
`tls` feature pulls in `rustls` and `rusty_tls` (and their transitive
crates), which raise the effective MSRV to whatever they require. The
optional `platform` feature
pulls in [`platform`](https://github.com/baileyrd/rustils) — rustils' own
hand-rolled OS abstraction layer, not a third-party framework, so it doesn't
compromise the dependency-free ethos the `tls` feature already establishes an
exception to — and similarly raises the effective MSRV to whatever `platform`
requires. It brings in the trait crate only; you add a concrete backend
(`platform-linux`, `platform-windows`, or `platform-mock`) yourself. See
[`src/platform_net.rs`](src/platform_net.rs) for the adapter. It also
enables `_with_csprng` siblings of every function that otherwise reads
`/dev/urandom` directly for its nonces/confounders —
`krb5::kdc::fetch_tgt_with_csprng`/`fetch_ap_req_with_csprng` and
`tls::connect_tls_with_csprng`/`connect_tls_kerberos_with_csprng` — each
taking a `platform::security::Csprng` backend in place of the file read.

The optional `serve-example` feature implies `platform` and additionally
pulls in the concrete `platform-linux` backend, purely to build
`examples/serve.rs` (see [Serving connections](#serving-connections) below);
it changes nothing about the core library's own dependencies.

## Connecting to a server

The `connect` example drives the deterministic part of the connection sequence
(X.224 negotiation, MCS connect, channel setup) against a live server:

```sh
cargo run --example connect -- 192.0.2.10:3389 alice
```

`RdpTransport::establish()` drives the whole standard-RDP bring-up
(negotiation → MCS → security exchange → encrypted logon → licensing →
capabilities → finalization) and returns an active session. The example then
pumps server updates with `recv_event()` — which accepts both slow-path and
fast-path framing — into a `Framebuffer` until the stream goes quiet and writes
the result to `screen.ppm`; `send_input()` sends keyboard/mouse events over
fast-path.

For a server that requires TLS, enable the `tls` feature and use
`connect_tls()` instead, which negotiates `SSL`, upgrades to TLS, and runs
`establish_enhanced()`:

```rust
# #[cfg(feature = "tls")]
# fn demo() -> std::io::Result<()> {
use rusty_rdp::net::EstablishConfig;
use rusty_rdp::nego::SecurityProtocols;
use rusty_rdp::tls::connect_tls;

let config = EstablishConfig::new(1024, 768, "", "alice", "secret");
let (mut transport, session) =
    connect_tls("192.0.2.10:3389", &config, SecurityProtocols::SSL)?;
let _ = (transport.recv_event()?, session);
# Ok(())
# }
```

## Serving connections

`RdpTransport::accept()` is this crate's server-side entry point, and the one
place that processes fully untrusted, attacker-controlled wire data end to
end (negotiation, GCC, the Security Exchange PDU, Client Info). The `serve`
example demonstrates driving it behind optional OS-level confinement from
`platform::security::Sandbox` (Landlock filesystem confinement, seccomp
`block_inet_sockets`) — bind the listening socket first, confine, then accept:

```sh
cargo run --example serve --features serve-example -- 127.0.0.1:3389
```

Confinement is Linux-only, and `block_inet_sockets` further requires
`x86_64`; `Sandbox` reports a three-way `SandboxStatus`
(`Enforced`/`NotEnforced`/`Unsupported`) instead of silently degrading, and
the example prints whichever it actually got rather than assuming
`Enforced`. On any other platform it prints that confinement isn't available
and runs unconfined. The example speaks only unencrypted standard RDP
security and exists to demonstrate the confinement pattern, not as a usable
server — do not point it at an untrusted network as-is.

## License

Licensed under either of MIT or Apache-2.0 at your option.
