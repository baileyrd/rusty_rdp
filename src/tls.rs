//! Optional TLS + CredSSP connector for the enhanced-security path (feature
//! `tls`).
//!
//! This is the crate's one concession to third-party dependencies, and it is
//! entirely opt-in: nothing here is compiled unless the `tls` feature is
//! enabled, so the default build stays dependency-free. A TLS stack is the one
//! piece that cannot be hand-rolled responsibly, so [`connect_tls`] wraps
//! [`rusty_tls`] — the shared TLS implementation and trust policy the rusty
//! ecosystem standardizes on — to upgrade the TCP stream before handing off
//! to [`RdpTransport::establish_enhanced`]. When the server selects
//! CredSSP/NLA (`HYBRID`), it runs the [`crate::credssp`] exchange over the
//! TLS channel first, delegating the user's credentials. The CredSSP crypto
//! (NTLMv2) is all in the dependency-free core; only the TLS bytes need the
//! crate.
//!
//! The RDP-over-TLS *protocol* logic still lives in the dependency-free core
//! ([`crate::net`]) — this module only supplies the bytes-on-wire TLS. If you
//! would rather not take the `rusty_tls`/`rustls` dependencies, wrap your
//! `TcpStream` in any TLS implementation yourself and call
//! [`RdpTransport::new_enhanced`] + [`RdpTransport::establish_enhanced`]
//! directly.
//!
//! Server-side TLS ([`accept_tls`]/[`accept_tls_nla`]) still builds directly
//! on `rustls` — `rusty_tls` has no server-side support yet.
//!
//! ## Certificate verification
//!
//! RDP servers overwhelmingly present self-signed certificates and rely on
//! out-of-band trust, so [`connect_tls`] uses
//! [`rusty_tls::TrustPolicy::DangerNoVerification`] — it does **not** verify
//! the server certificate. That means it does not protect against an active
//! man-in-the-middle. If you need verification, build your own TLS stream
//! (`rusty_tls::TlsStream::new` with `TrustPolicy::System` or
//! `TrustPolicy::PinnedAnchors`) and use the [`RdpTransport::new_enhanced`]
//! path.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::credssp::{self, CredSspClient, CredSspServer, KerberosCredSspClient};
use crate::krb5::aes::AesKey;
use crate::nego::SecurityProtocols;
use crate::net::{EstablishConfig, RdpSession, RdpTransport};

/// The TLS-wrapped stream type an established enhanced-security session runs
/// over.
pub type TlsStream = rusty_tls::TlsStream<TcpStream>;

/// Connect to an RDP server over TLS and drive the enhanced-security bring-up.
///
/// Opens a TCP connection to `addr` (a `host:port` string), performs the
/// X.224 negotiation requesting `requested`, upgrades the stream to TLS, runs
/// the CredSSP/NLA exchange if the server selected `HYBRID`, and finishes with
/// [`RdpTransport::establish_enhanced`]. Returns the live transport and its
/// [`RdpSession`].
///
/// Pass `requested` = `SSL | HYBRID` to allow either; a server that falls back
/// to standard RDP security returns an error pointing at
/// [`RdpTransport::establish`].
///
/// The server certificate is **not** verified — see the [module
/// docs](self#certificate-verification).
pub fn connect_tls(
    addr: &str,
    config: &EstablishConfig,
    requested: SecurityProtocols,
) -> io::Result<(RdpTransport<TlsStream>, RdpSession)> {
    connect_tls_impl(addr, config, requested, run_credssp)
}

/// Like [`connect_tls`], but draws the CredSSP exchange's nonce/challenge/key
/// from `csprng` instead of opening `/dev/urandom` directly. Requires the
/// optional `platform` feature (on top of this module's own `tls` feature).
#[cfg(feature = "platform")]
pub fn connect_tls_with_csprng(
    addr: &str,
    config: &EstablishConfig,
    requested: SecurityProtocols,
    csprng: &dyn platform::security::Csprng,
) -> io::Result<(RdpTransport<TlsStream>, RdpSession)> {
    connect_tls_impl(addr, config, requested, |tls, config| {
        run_credssp_with_csprng(tls, config, csprng)
    })
}

/// The shared body of [`connect_tls`]/[`connect_tls_with_csprng`]: the only
/// difference between the two is how the CredSSP exchange (`run_credssp`)
/// obtains its randomness, so that step is the one thing passed in.
fn connect_tls_impl(
    addr: &str,
    config: &EstablishConfig,
    requested: SecurityProtocols,
    run_credssp: impl FnOnce(&mut TlsStream, &EstablishConfig) -> io::Result<()>,
) -> io::Result<(RdpTransport<TlsStream>, RdpSession)> {
    // Host portion of `host:port`, for the TLS server name.
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);

    // 1. X.224 negotiation happens on the raw TCP connection, before TLS.
    let tcp = TcpStream::connect(addr)?;
    let mut pre = RdpTransport::new(tcp);
    let selected = pre.negotiate(requested, Some(&config.username))?;
    let use_nla = match selected {
        s if s == SecurityProtocols::SSL => false,
        s if s == SecurityProtocols::HYBRID || s == SecurityProtocols::HYBRID_EX => true,
        s if s == SecurityProtocols::RDP => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "server selected standard RDP security; use RdpTransport::establish instead",
            ));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("server selected unsupported protocol {other:?}"),
            ));
        }
    };
    let tcp = pre.into_inner();

    // 2. Upgrade the same TCP connection to TLS. See the module docs for
    //    why `DangerNoVerification`: RDP servers overwhelmingly present
    //    self-signed certificates and rely on out-of-band trust.
    let mut tls =
        rusty_tls::TlsStream::new(tcp, host, &rusty_tls::TrustPolicy::DangerNoVerification)?;

    // 3. If the server chose CredSSP, authenticate before the RDP sequence.
    if use_nla {
        run_credssp(&mut tls, config)?;
    }

    // 4. Everything from MCS onward runs inside the TLS tunnel.
    let mut transport = RdpTransport::new_enhanced(tls);
    let session = transport.establish_enhanced(config, selected)?;
    Ok((transport, session))
}

/// The shared tail of [`run_credssp`]/[`run_credssp_with_csprng`]: complete
/// the TLS handshake, fetch the server's public key, and drive the NTLM
/// CredSSP exchange with `seed` split into the nonce/challenge/key it needs.
fn run_credssp_with_seed(
    tls: &mut TlsStream,
    config: &EstablishConfig,
    seed: [u8; 56],
) -> io::Result<()> {
    // Complete the TLS handshake so the server certificate is available.
    tls.complete_handshake()?;
    let public_key = server_public_key(tls)?;

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&seed[..32]);
    let mut client_challenge = [0u8; 8];
    client_challenge.copy_from_slice(&seed[32..40]);
    let mut exported_session_key = [0u8; 16];
    exported_session_key.copy_from_slice(&seed[40..56]);

    let mut client = CredSspClient::new(
        &config.domain,
        &config.username,
        &config.password,
        &config.client_name,
        public_key,
        nonce,
        client_challenge,
        filetime_now(),
        exported_session_key,
    );

    // Leg 1: NTLM NEGOTIATE.
    tls.write_all(&client.negotiate_request())?;
    tls.flush()?;
    // Leg 2 → Leg 3: CHALLENGE in, AUTHENTICATE + pubKeyAuth out.
    let leg2 = read_ts_request(tls)?;
    let leg3 = client.challenge_response(&leg2).map_err(to_io)?;
    tls.write_all(&leg3)?;
    tls.flush()?;
    // Leg 4 → Leg 5: server public-key confirmation in, credentials out.
    let leg4 = read_ts_request(tls)?;
    let leg5 = client.finish(&leg4).map_err(to_io)?;
    tls.write_all(&leg5)?;
    tls.flush()?;
    Ok(())
}

/// Run the CredSSP/NLA exchange over an established TLS stream, delegating the
/// user's credentials so the RDP connection sequence can proceed. Gathers its
/// nonce/challenge/key from `/dev/urandom`; [`run_credssp_with_csprng`] is the
/// `platform`-feature alternative.
fn run_credssp(tls: &mut TlsStream, config: &EstablishConfig) -> io::Result<()> {
    let mut seed = [0u8; 56];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    run_credssp_with_seed(tls, config, seed)
}

/// Like [`run_credssp`], but draws `seed` from `csprng` instead of opening
/// `/dev/urandom` directly.
#[cfg(feature = "platform")]
fn run_credssp_with_csprng(
    tls: &mut TlsStream,
    config: &EstablishConfig,
    csprng: &dyn platform::security::Csprng,
) -> io::Result<()> {
    let mut seed = [0u8; 56];
    csprng
        .fill_random(&mut seed)
        .map_err(crate::platform_net::to_io_error)?;
    run_credssp_with_seed(tls, config, seed)
}

/// Connect to an RDP server over TLS using a Kerberos ticket for NLA.
///
/// Same as [`connect_tls`] but authenticates with Kerberos instead of NTLM:
/// negotiates `HYBRID`, upgrades to TLS, runs the CredSSP exchange with the
/// caller-provided `AP-REQ` and its `session_key` (obtain these from a KDC or
/// a credential cache — fetching them is out of scope), and finishes with
/// [`RdpTransport::establish_enhanced`].
///
/// The server certificate is **not** verified — see the [module
/// docs](self#certificate-verification).
pub fn connect_tls_kerberos(
    addr: &str,
    config: &EstablishConfig,
    ap_req: Vec<u8>,
    session_key: AesKey,
) -> io::Result<(RdpTransport<TlsStream>, RdpSession)> {
    connect_tls_kerberos_impl(addr, config, move |tls, config| {
        run_credssp_kerberos(tls, config, ap_req, session_key)
    })
}

/// Like [`connect_tls_kerberos`], but draws the CredSSP exchange's nonce and
/// two GSS confounders from `csprng` instead of opening `/dev/urandom`
/// directly. Requires the optional `platform` feature (on top of this
/// module's own `tls` feature).
#[cfg(feature = "platform")]
pub fn connect_tls_kerberos_with_csprng(
    addr: &str,
    config: &EstablishConfig,
    ap_req: Vec<u8>,
    session_key: AesKey,
    csprng: &dyn platform::security::Csprng,
) -> io::Result<(RdpTransport<TlsStream>, RdpSession)> {
    connect_tls_kerberos_impl(addr, config, move |tls, config| {
        run_credssp_kerberos_with_csprng(tls, config, ap_req, session_key, csprng)
    })
}

/// The shared body of [`connect_tls_kerberos`]/[`connect_tls_kerberos_with_csprng`].
fn connect_tls_kerberos_impl(
    addr: &str,
    config: &EstablishConfig,
    run_credssp_kerberos: impl FnOnce(&mut TlsStream, &EstablishConfig) -> io::Result<()>,
) -> io::Result<(RdpTransport<TlsStream>, RdpSession)> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);

    // Negotiate HYBRID on the raw TCP connection.
    let tcp = TcpStream::connect(addr)?;
    let mut pre = RdpTransport::new(tcp);
    let selected = pre.negotiate(SecurityProtocols::HYBRID, Some(&config.username))?;
    if selected != SecurityProtocols::HYBRID && selected != SecurityProtocols::HYBRID_EX {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("server did not select CredSSP/HYBRID (got {selected:?})"),
        ));
    }
    let tcp = pre.into_inner();

    let mut tls =
        rusty_tls::TlsStream::new(tcp, host, &rusty_tls::TrustPolicy::DangerNoVerification)?;

    run_credssp_kerberos(&mut tls, config)?;

    let mut transport = RdpTransport::new_enhanced(tls);
    let session = transport.establish_enhanced(config, selected)?;
    Ok((transport, session))
}

/// The TLS-wrapped stream type an [`accept_tls`]-accepted connection runs
/// over.
pub type TlsServerStream = StreamOwned<ServerConnection, TcpStream>;

/// Accept an RDP client over TLS: negotiate [`SecurityProtocols::SSL`] on
/// `tcp`, upgrade to TLS using `tls_config`, and drive the rest of the
/// server-side connection sequence via [`RdpTransport::accept`]'s shared
/// post-negotiation logic.
///
/// `tls_config` supplies the server's certificate and private key (build it
/// with [`rustls::ServerConfig::builder`] — this crate does not generate
/// X.509 certificates itself, matching how [`connect_tls`] does not verify
/// them). Leave `config.encryption` (in `accept_config`) as `None`: TLS
/// already provides confidentiality, and the standard-security RSA/RC4 path
/// is mutually exclusive with Enhanced RDP Security per MS-RDPBCGR.
///
/// CredSSP/NLA (`HYBRID`) is not offered — only plain TLS
/// ([`SecurityProtocols::SSL`]) is negotiated, and the connection is rejected
/// (with an `RDP_NEG_FAILURE`) if the client doesn't offer it.
pub fn accept_tls(
    tcp: TcpStream,
    tls_config: Arc<ServerConfig>,
    accept_config: &crate::net::AcceptConfig,
) -> io::Result<(RdpTransport<TlsServerStream>, crate::net::AcceptedClient)> {
    let mut pre = RdpTransport::new(tcp);
    pre.accept_negotiate_ssl()?;
    let tcp = pre.into_inner();

    let conn = ServerConnection::new(tls_config)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS setup failed: {e}")))?;
    let tls = StreamOwned::new(conn, tcp);

    let mut transport = RdpTransport::new_enhanced(tls);
    let client = transport.accept_after_negotiate(accept_config)?;
    Ok((transport, client))
}

/// A client's identity delegated over CredSSP/NLA by [`accept_tls_nla`]:
/// the domain, username, and password decrypted from the client's
/// `authInfo`.
///
/// [`CredSspServer`] (which [`accept_tls_nla`] drives) has already verified
/// the client knows the account's password (via the `hash_lookup` callback
/// passed to it), but this crate does not maintain an account database or
/// decide who is allowed to log on — that, and actually logging the user on,
/// is the caller's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlaIdentity {
    /// Logon domain (may be empty).
    pub domain: String,
    /// Logon user name.
    pub user: String,
    /// Logon password.
    pub password: String,
}

/// Accept an RDP client over CredSSP/NLA: negotiate
/// [`SecurityProtocols::HYBRID`] on `tcp`, upgrade to TLS using
/// `tls_config`, run the CredSSP exchange via `credssp` (verifying the
/// client's NTLM authentication and recovering its delegated credentials),
/// and then drive the rest of the server-side connection sequence via
/// [`RdpTransport::accept`]'s shared post-negotiation logic — the same
/// three pieces [`accept_tls`] composes, plus the CredSSP leg in between.
///
/// Build `credssp` with [`CredSspServer::new`], passing this server's own
/// `SubjectPublicKeyInfo` as its `public_key` argument — extract that from
/// the same certificate DER used to build `tls_config` with [`extract_spki`].
/// On authentication failure, the client is sent an `errorCode` `TSRequest`
/// ([`credssp::STATUS_LOGON_FAILURE`]) before this returns `Err`.
///
/// As with [`accept_tls`], leave `accept_config.encryption` as `None`: TLS
/// (here, on top of CredSSP) already provides confidentiality.
///
/// `HYBRID_EX`'s Early User Authorization Result PDU is not sent — only the
/// base `HYBRID` protocol is offered, and rejected (with an
/// `RDP_NEG_FAILURE`) if the client doesn't support it.
pub fn accept_tls_nla<F: Fn(&str, &str) -> Option<[u8; 16]>>(
    tcp: TcpStream,
    tls_config: Arc<ServerConfig>,
    mut credssp: CredSspServer<F>,
    accept_config: &crate::net::AcceptConfig,
) -> io::Result<(
    RdpTransport<TlsServerStream>,
    crate::net::AcceptedClient,
    NlaIdentity,
)> {
    let mut pre = RdpTransport::new(tcp);
    pre.accept_negotiate_hybrid()?;
    let tcp = pre.into_inner();

    let conn = ServerConnection::new(tls_config)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS setup failed: {e}")))?;
    let mut tls = StreamOwned::new(conn, tcp);

    while tls.conn.is_handshaking() {
        if tls.conn.complete_io(&mut tls.sock)?.0 == 0 && tls.conn.is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS handshake stalled",
            ));
        }
    }

    let identity = run_credssp_server(&mut tls, &mut credssp)?;

    let mut transport = RdpTransport::new_enhanced(tls);
    let client = transport.accept_after_negotiate(accept_config)?;
    Ok((transport, client, identity))
}

/// Drive [`CredSspServer`]'s three legs over an established TLS stream. On
/// [`CredSspServer::verify_authenticate`] failure, tells the client via an
/// `errorCode` `TSRequest` before returning the error.
fn run_credssp_server<F: Fn(&str, &str) -> Option<[u8; 16]>>(
    tls: &mut TlsServerStream,
    credssp: &mut CredSspServer<F>,
) -> io::Result<NlaIdentity> {
    let leg1 = read_ts_request(tls)?;
    let leg2 = credssp.challenge_response(&leg1).map_err(to_io)?;
    tls.write_all(&leg2)?;
    tls.flush()?;

    let leg3 = read_ts_request(tls)?;
    let leg4 = match credssp.verify_authenticate(&leg3) {
        Ok(bytes) => bytes,
        Err(e) => {
            let error_response = credssp::encode_error_response(credssp::STATUS_LOGON_FAILURE);
            let _ = tls.write_all(&error_response);
            let _ = tls.flush();
            return Err(to_io(e));
        }
    };
    tls.write_all(&leg4)?;
    tls.flush()?;

    let leg5 = read_ts_request(tls)?;
    let (domain, user, password) = credssp.finish(&leg5).map_err(to_io)?;
    Ok(NlaIdentity {
        domain,
        user,
        password,
    })
}

/// The shared tail of [`run_credssp_kerberos`]/[`run_credssp_kerberos_with_csprng`]:
/// complete the TLS handshake, fetch the server's public key, and drive the
/// Kerberos CredSSP exchange with `seed` split into the nonce and two GSS
/// confounders it needs.
fn run_credssp_kerberos_with_seed(
    tls: &mut TlsStream,
    config: &EstablishConfig,
    ap_req: Vec<u8>,
    session_key: AesKey,
    seed: [u8; 64],
) -> io::Result<()> {
    tls.complete_handshake()?;
    let public_key = server_public_key(tls)?;

    // Nonce plus two 16-byte GSS confounders.
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&seed[..32]);
    let conf1 = &seed[32..48];
    let conf2 = &seed[48..64];

    let mut client = KerberosCredSspClient::new(
        session_key,
        ap_req,
        public_key,
        nonce,
        &config.domain,
        &config.username,
        &config.password,
    );

    // Leg 1: SPNEGO/AP-REQ + sealed public key.
    tls.write_all(&client.initial_request(conf1))?;
    tls.flush()?;
    // Leg 2 → Leg 3: AP-REP + server public key in, sealed credentials out.
    let leg2 = read_ts_request(tls)?;
    let leg3 = client.finish(&leg2, conf2).map_err(to_io)?;
    tls.write_all(&leg3)?;
    tls.flush()?;
    Ok(())
}

/// Run the Kerberos CredSSP exchange over an established TLS stream. Gathers
/// its nonce/confounders from `/dev/urandom`; [`run_credssp_kerberos_with_csprng`]
/// is the `platform`-feature alternative.
fn run_credssp_kerberos(
    tls: &mut TlsStream,
    config: &EstablishConfig,
    ap_req: Vec<u8>,
    session_key: AesKey,
) -> io::Result<()> {
    let mut seed = [0u8; 64];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    run_credssp_kerberos_with_seed(tls, config, ap_req, session_key, seed)
}

/// Like [`run_credssp_kerberos`], but draws `seed` from `csprng` instead of
/// opening `/dev/urandom` directly.
#[cfg(feature = "platform")]
fn run_credssp_kerberos_with_csprng(
    tls: &mut TlsStream,
    config: &EstablishConfig,
    ap_req: Vec<u8>,
    session_key: AesKey,
    csprng: &dyn platform::security::Csprng,
) -> io::Result<()> {
    let mut seed = [0u8; 64];
    csprng
        .fill_random(&mut seed)
        .map_err(crate::platform_net::to_io_error)?;
    run_credssp_kerberos_with_seed(tls, config, ap_req, session_key, seed)
}

/// The Windows FILETIME (100 ns since 1601-01-01) for the current time.
fn filetime_now() -> [u8; 8] {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = (unix.as_secs() + EPOCH_DIFF_SECS)
        .wrapping_mul(10_000_000)
        .wrapping_add(unix.subsec_nanos() as u64 / 100);
    ticks.to_le_bytes()
}

/// Read one complete DER `TSRequest` (a definite-length SEQUENCE) from the
/// stream.
fn read_ts_request<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected TSRequest SEQUENCE",
        ));
    }
    let mut out = vec![header[0], header[1]];
    let content_len = if header[1] & 0x80 == 0 {
        header[1] as usize
    } else {
        let n = (header[1] & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DER length"));
        }
        let mut lenbuf = vec![0u8; n];
        stream.read_exact(&mut lenbuf)?;
        out.extend_from_slice(&lenbuf);
        lenbuf
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize)
    };
    let start = out.len();
    out.resize(start + content_len, 0);
    stream.read_exact(&mut out[start..])?;
    Ok(out)
}

/// Extract the server's `SubjectPublicKeyInfo` DER from the TLS peer
/// certificate, for the CredSSP channel binding.
fn server_public_key(tls: &TlsStream) -> io::Result<Vec<u8>> {
    let cert = tls
        .peer_certificate_der()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no server certificate presented"))?;
    extract_spki(cert)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cannot parse certificate"))
}

/// Split one DER TLV (single-byte tag), returning `(whole, content, rest)`.
fn split_tlv(buf: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let first = buf[1];
    let (len, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let len = buf[2..2 + n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    Some((&buf[..end], &buf[header..end], &buf[end..]))
}

/// Extract the `SubjectPublicKeyInfo` from an X.509 certificate DER.
///
/// Walks `Certificate → tbsCertificate`, skips the optional version, serial
/// number, and the four SEQUENCEs (signature, issuer, validity, subject), and
/// returns the following SEQUENCE (the SPKI) verbatim. Used internally to
/// extract the *peer's* public key for the CredSSP channel binding; exposed
/// publicly so a server can extract the same bytes from its *own*
/// certificate for [`CredSspServer::new`]'s `public_key` argument (see
/// [`accept_tls_nla`]).
pub fn extract_spki(cert: &[u8]) -> Option<Vec<u8>> {
    let (_, cert_content, _) = split_tlv(cert)?; // Certificate
    let (_, tbs, _) = split_tlv(cert_content)?; // tbsCertificate
    let mut cur = tbs;
    if cur.first() == Some(&0xA0) {
        // [0] EXPLICIT version
        let (_, _, rest) = split_tlv(cur)?;
        cur = rest;
    }
    // serialNumber INTEGER
    let (_, _, rest) = split_tlv(cur)?;
    cur = rest;
    // signature, issuer, validity, subject — four SEQUENCEs.
    for _ in 0..4 {
        let (_, _, rest) = split_tlv(cur)?;
        cur = rest;
    }
    let (spki, _, _) = split_tlv(cur)?;
    Some(spki.to_vec())
}

/// Map a codec [`crate::Error`] into an [`io::Error`].
fn to_io(e: crate::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credssp::TsRequest;

    // A throwaway self-signed P-256 cert/key pair (10-year validity, CN
    // "localhost"), generated once with:
    //   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
    //   openssl req -x509 -key key.pem -out cert.pem -days 3650 -subj /CN=localhost
    //   openssl x509 -in cert.pem -outform der -out cert.der
    //   openssl pkcs8 -topk8 -nocrypt -in key.pem -outform der -out key.der
    // Not a secret — used only to exercise `accept_tls` in tests.
    #[rustfmt::skip]
    const TEST_TLS_CERT_DER: [u8; 384] = [
        0x30, 0x82, 0x01, 0x7c, 0x30, 0x82, 0x01, 0x23, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x04,
        0x5f, 0xfe, 0x42, 0xf9, 0x1c, 0xb6, 0xe0, 0x4c, 0x27, 0x2c, 0xd5, 0xf9, 0x03, 0x9f, 0xac, 0x32,
        0x02, 0xfb, 0xd8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x31, 0x38, 0x30,
        0x32, 0x35, 0x38, 0x35, 0x35, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x37, 0x31, 0x35, 0x30, 0x32,
        0x35, 0x38, 0x35, 0x35, 0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06,
        0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x95, 0xb3, 0x50, 0x31, 0x00, 0x17, 0x4d, 0xe1, 0xda, 0x1d,
        0xe6, 0x25, 0xc9, 0xfb, 0xac, 0xf4, 0x73, 0x05, 0x01, 0x98, 0xfd, 0x6c, 0x68, 0x4d, 0x1e, 0xe5,
        0xf7, 0x73, 0xba, 0xa3, 0x1c, 0x55, 0x45, 0xff, 0x8d, 0x54, 0x8e, 0xb7, 0x7b, 0x84, 0xc2, 0xc2,
        0x75, 0x27, 0x6d, 0x44, 0x81, 0xd3, 0xd4, 0x30, 0xc1, 0x58, 0x60, 0xf7, 0x66, 0x6c, 0x15, 0xde,
        0xbb, 0x4c, 0x2a, 0x3d, 0x02, 0xf1, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x0e, 0x04, 0x16, 0x04, 0x14, 0xf1, 0x7e, 0x75, 0xcd, 0xa0, 0x46, 0xba, 0x1f, 0xc7, 0xdd, 0x36,
        0xb3, 0x44, 0xea, 0xd2, 0x64, 0xb7, 0xed, 0x15, 0xb5, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
        0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xf1, 0x7e, 0x75, 0xcd, 0xa0, 0x46, 0xba, 0x1f, 0xc7, 0xdd,
        0x36, 0xb3, 0x44, 0xea, 0xd2, 0x64, 0xb7, 0xed, 0x15, 0xb5, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
        0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x53, 0x26,
        0xde, 0x5a, 0x53, 0x4f, 0xa1, 0x9a, 0xdb, 0x17, 0xf2, 0x9a, 0x78, 0xba, 0xca, 0x63, 0x9b, 0x30,
        0xa2, 0xa5, 0xfd, 0xff, 0x57, 0x80, 0x5c, 0x4a, 0xfe, 0x9e, 0xb4, 0xac, 0x36, 0xa0, 0x02, 0x20,
        0x12, 0xf1, 0xa3, 0x55, 0x84, 0xf7, 0xf9, 0xe5, 0x58, 0xd8, 0x0d, 0xbf, 0x9e, 0xc9, 0x6a, 0xbf,
        0x31, 0x4b, 0x98, 0xc0, 0xfe, 0x9d, 0x3b, 0x98, 0xf8, 0x79, 0xf2, 0xa6, 0x90, 0xd9, 0x4a, 0x7d,
    ];

    #[rustfmt::skip]
    const TEST_TLS_KEY_PKCS8_DER: [u8; 138] = [
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
        0x01, 0x01, 0x04, 0x20, 0xce, 0x21, 0x00, 0x96, 0xa5, 0x3d, 0x7f, 0xc4, 0x50, 0xb8, 0xdb, 0xec,
        0xbf, 0xd9, 0x63, 0x01, 0xf5, 0x60, 0xd3, 0x6d, 0x22, 0xce, 0xb6, 0x76, 0xd3, 0x45, 0x47, 0xb0,
        0x46, 0x64, 0x64, 0x1e, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x95, 0xb3, 0x50, 0x31, 0x00, 0x17,
        0x4d, 0xe1, 0xda, 0x1d, 0xe6, 0x25, 0xc9, 0xfb, 0xac, 0xf4, 0x73, 0x05, 0x01, 0x98, 0xfd, 0x6c,
        0x68, 0x4d, 0x1e, 0xe5, 0xf7, 0x73, 0xba, 0xa3, 0x1c, 0x55, 0x45, 0xff, 0x8d, 0x54, 0x8e, 0xb7,
        0x7b, 0x84, 0xc2, 0xc2, 0x75, 0x27, 0x6d, 0x44, 0x81, 0xd3, 0xd4, 0x30, 0xc1, 0x58, 0x60, 0xf7,
        0x66, 0x6c, 0x15, 0xde, 0xbb, 0x4c, 0x2a, 0x3d, 0x02, 0xf1,
    ];

    fn test_tls_server_config() -> Arc<ServerConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let cert = CertificateDer::from(TEST_TLS_CERT_DER.to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(TEST_TLS_KEY_PKCS8_DER.to_vec()));
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("test cert/key should build a valid ServerConfig"),
        )
    }

    #[test]
    fn accept_tls_rejects_client_that_did_not_offer_ssl() {
        use crate::net::AcceptConfig;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let config = AcceptConfig::new(1024, 768);
            accept_tls(stream, test_tls_server_config(), &config)
        });

        // A bare client that skips negotiation entirely (i.e. never offers
        // SSL) should be rejected.
        let stream = TcpStream::connect(addr).unwrap();
        let mut client = RdpTransport::new(stream);
        let _ = client.negotiate(SecurityProtocols::RDP, None);

        let result = server.join().unwrap();
        assert!(result.is_err(), "accept_tls should reject a non-TLS client");
    }

    #[test]
    fn accept_tls_completes_full_connection_sequence_with_connect_tls() {
        use crate::net::AcceptConfig;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let config = AcceptConfig::new(1024, 768);
            let (transport, accepted) =
                accept_tls(stream, test_tls_server_config(), &config).unwrap();
            (accepted, transport.get_ref().conn.is_handshaking())
        });

        let establish_config = EstablishConfig::new(1024, 768, "CORP", "alice", "secret");
        let (_transport, session) =
            connect_tls(&addr.to_string(), &establish_config, SecurityProtocols::SSL).unwrap();

        let (accepted, server_still_handshaking) = server.join().unwrap();
        assert!(
            !server_still_handshaking,
            "TLS handshake should be complete after accept_after_negotiate"
        );
        assert_eq!(accepted.user_id, session.user_id);
        assert_eq!(accepted.io_channel, session.io_channel);
        assert_eq!(accepted.share_id, session.share_id);
        assert_eq!(accepted.client_info.username, "alice");
        assert_eq!(accepted.client_info.domain, "CORP");
    }

    type HashLookupFn = fn(&str, &str) -> Option<[u8; 16]>;

    fn test_credssp_server() -> CredSspServer<HashLookupFn> {
        let public_key = extract_spki(&TEST_TLS_CERT_DER).unwrap();
        CredSspServer::new(
            "SRV",
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            [0u8; 8],
            public_key,
            |domain: &str, user: &str| {
                if domain == "CORP" && user == "alice" {
                    Some(crate::ntlm::nt_hash("secret"))
                } else {
                    None
                }
            },
        )
    }

    #[test]
    fn accept_tls_nla_completes_full_connection_sequence_with_connect_tls() {
        use crate::net::AcceptConfig;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let config = AcceptConfig::new(1024, 768);
            accept_tls_nla(
                stream,
                test_tls_server_config(),
                test_credssp_server(),
                &config,
            )
            .unwrap()
        });

        let establish_config = EstablishConfig::new(1024, 768, "CORP", "alice", "secret");
        let (_transport, session) = connect_tls(
            &addr.to_string(),
            &establish_config,
            SecurityProtocols::HYBRID,
        )
        .unwrap();

        let (_transport, accepted, identity) = server.join().unwrap();
        assert_eq!(accepted.share_id, session.share_id);
        assert_eq!(accepted.client_info.username, "alice");
        assert_eq!(accepted.client_info.domain, "CORP");
        assert_eq!(identity.domain, "CORP");
        assert_eq!(identity.user, "alice");
        assert_eq!(identity.password, "secret");
    }

    #[cfg(feature = "platform")]
    #[test]
    fn connect_tls_with_csprng_completes_full_connection_sequence() {
        use crate::net::AcceptConfig;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let config = AcceptConfig::new(1024, 768);
            accept_tls_nla(
                stream,
                test_tls_server_config(),
                test_credssp_server(),
                &config,
            )
            .unwrap()
        });

        let establish_config = EstablishConfig::new(1024, 768, "CORP", "alice", "secret");
        let csprng = platform_mock::MockCsprng::new();
        let (_transport, session) = connect_tls_with_csprng(
            &addr.to_string(),
            &establish_config,
            SecurityProtocols::HYBRID,
            &csprng,
        )
        .unwrap();

        let (_transport, accepted, identity) = server.join().unwrap();
        assert_eq!(accepted.share_id, session.share_id);
        assert_eq!(accepted.client_info.username, "alice");
        assert_eq!(accepted.client_info.domain, "CORP");
        assert_eq!(identity.domain, "CORP");
        assert_eq!(identity.user, "alice");
        assert_eq!(identity.password, "secret");
    }

    #[test]
    fn accept_tls_nla_rejects_wrong_password() {
        use crate::net::AcceptConfig;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let config = AcceptConfig::new(1024, 768);
            accept_tls_nla(
                stream,
                test_tls_server_config(),
                test_credssp_server(),
                &config,
            )
        });

        let establish_config = EstablishConfig::new(1024, 768, "CORP", "alice", "wrong-password");
        let client_result = connect_tls(
            &addr.to_string(),
            &establish_config,
            SecurityProtocols::HYBRID,
        );
        assert!(client_result.is_err());
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn accept_tls_nla_rejects_client_that_did_not_offer_hybrid() {
        use crate::net::AcceptConfig;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let config = AcceptConfig::new(1024, 768);
            accept_tls_nla(
                stream,
                test_tls_server_config(),
                test_credssp_server(),
                &config,
            )
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut client = RdpTransport::new(stream);
        let _ = client.negotiate(SecurityProtocols::SSL, None);

        assert!(server.join().unwrap().is_err());
    }

    /// Build a DER TLV with a single-byte tag and short-form length.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }

    #[test]
    fn extract_spki_walks_certificate() {
        // Minimal Certificate { tbsCertificate { [0]ver, serial, sig, issuer,
        // validity, subject, spki }, sigAlg, sigValue }.
        let version = tlv(0xA0, &tlv(0x02, &[0x02])); // [0] { INTEGER 2 }
        let serial = tlv(0x02, &[0x01]);
        let seq_empty = tlv(0x30, &[]);
        let spki = tlv(0x30, &[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial);
        for _ in 0..4 {
            tbs.extend_from_slice(&seq_empty); // sig, issuer, validity, subject
        }
        tbs.extend_from_slice(&spki);

        let mut cert_content = tlv(0x30, &tbs);
        cert_content.extend_from_slice(&seq_empty); // signatureAlgorithm
        cert_content.extend_from_slice(&tlv(0x03, &[0x00])); // signatureValue
        let cert = tlv(0x30, &cert_content);

        assert_eq!(extract_spki(&cert), Some(spki));
    }

    #[test]
    fn read_ts_request_short_and_long_form() {
        // Short form (< 128 bytes of content).
        let small = TsRequest {
            version: 6,
            nego_tokens: vec![vec![1, 2, 3]],
            ..Default::default()
        }
        .to_vec();
        let mut cursor = io::Cursor::new(small.clone());
        assert_eq!(read_ts_request(&mut cursor).unwrap(), small);

        // Long form (a token large enough to force a multi-byte length).
        let big = TsRequest {
            version: 6,
            nego_tokens: vec![vec![0xAB; 300]],
            ..Default::default()
        }
        .to_vec();
        assert!(big[1] & 0x80 != 0, "expected long-form length");
        let mut cursor = io::Cursor::new(big.clone());
        assert_eq!(read_ts_request(&mut cursor).unwrap(), big);
    }
}
