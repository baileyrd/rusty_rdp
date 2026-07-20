//! # rusty_rdp
//!
//! A minimal, **dependency-free** implementation of the Remote Desktop
//! Protocol (RDP) wire format.
//!
//! The crate has zero third-party dependencies — only the Rust standard
//! library — and every wire structure is encoded and decoded by hand with
//! bounds-checked cursors. `unsafe` is forbidden crate-wide.
//!
//! ## Layering
//!
//! RDP is a stack of nested framings carried over a single TCP connection.
//! This crate models the lower layers first; higher layers are added on top
//! without changing what is already here.
//!
//! ```text
//! TCP stream
//!   └─ TPKT           (crate::tpkt)   4-byte length framing
//!        └─ X.224     (crate::x224)   Class 0 CR / CC / Data TPDUs
//!             └─ RDP negotiation      (crate::nego)  security selection
//!             └─ MCS                  (crate::mcs)   Connect + domain PDUs
//!                  ├─ BER codec       (crate::ber)   Connect-Initial/Response
//!                  ├─ PER codec       (crate::per)   domain PDUs
//!                  └─ GCC             (crate::gcc)   T.124 conference + blocks
//!             └─ security             (crate::security)  standard RC4/RSA
//!             └─ Client Info          (crate::client_info)  logon
//!             └─ licensing            (crate::license)   license exchange
//!             └─ Share Control/Data   (crate::pdu)   session PDU framing
//!                  ├─ capabilities    (crate::capabilities)  Demand/Confirm Active
//!                  ├─ finalization    (crate::finalization)  sync/control/font
//!                  ├─ input           (crate::input)  keyboard / mouse events
//!                  ├─ pointer         (crate::pointer)  cursor updates
//!                  └─ output          (crate::output)  bitmap / palette updates
//!                       ├─ RLE decode   (crate::rle)  interleaved bitmap codec
//!                       ├─ pixel unpack (crate::pixel)  native format → RGBA
//!                       └─ framebuffer  (crate::display)  blit rects to a surface
//!             └─ fast-path            (crate::fastpath)  compact input/output framing
//!             └─ virtual channels     (crate::vchan)  MS-RDPBCGR chunking, any static channel
//!                  └─ clipboard         (crate::cliprdr)  MS-RDPECLIP redirection PDUs
//!                  └─ audio             (crate::rdpsnd)  MS-RDPEA redirection PDUs
//!                  └─ device redirection (crate::rdpdr)  MS-RDPEFS init/capability handshake + Device I/O Request/Response + file/volume/directory ops
//!                  └─ dynamic channels (crate::dvc)  MS-RDPEDYC framing (RDPGFX, redirection)
//!                       └─ session mgmt (crate::dvcman)  open-channel bookkeeping
//!                            └─ graphics pipeline (crate::gfx)  MS-RDPEGFX caps/surface/cache/composition/output-mapping PDUs + AVC420/444 wrapper metadata
//!                                 └─ RemoteFX codec (crate::rfx)  MS-RDPRFX RLGR1/RLGR3+DWT tile decode + control PDUs
//!                                 └─ Planar codec (crate::planar)  MS-RDPEGDI RDP 6.0 bitmap plane/RLE decode
//!                                 └─ ClearCodec (crate::clearcodec)  MS-RDPEGFX residual/bands/subcodec decode + glyph/VBar caches
//! ```
//!
//! For the enhanced-security (TLS/CredSSP) path, the negotiation runs on the
//! raw TCP connection and the stream is upgraded to TLS; NTLMv2
//! ([`crate::ntlm`]) and CredSSP ([`crate::credssp`]) then authenticate inside
//! the tunnel before the MCS sequence. The TLS bytes are the one thing behind
//! an optional feature (`tls`); every codec and the NTLM/CredSSP crypto stay
//! dependency-free.
//!
//! [`net::RdpTransport::accept`] drives the same connection sequence in
//! reverse, as a server, over the identical bidirectional codec types —
//! either unencrypted standard RDP security (`encryptionLevel = 0`) or, with
//! caller-supplied RSA key material, real encrypted standard security (RSA
//! exchange + RC4). Two TLS-upgrading counterparts to `accept` (feature
//! `tls`) share its post-negotiation logic: `crate::tls::accept_tls`
//! negotiates [`nego::SecurityProtocols::SSL`] and upgrades the stream with
//! a caller-supplied `rustls::ServerConfig` (certificate + private key);
//! `crate::tls::accept_tls_nla` does the same for
//! [`nego::SecurityProtocols::HYBRID`], additionally running
//! `crate::credssp::CredSspServer` (NTLM only, verified against a
//! caller-supplied password-hash callback) over the TLS stream first and
//! returning the delegated identity. Kerberos is not supported
//! server-side.
//!
//! ## Design
//!
//! * **No I/O in the codec.** Every type encodes to and decodes from byte
//!   slices, so the same code works with blocking sockets, async runtimes,
//!   or in-memory tests. [`tpkt::Tpkt::peek_total_len`] lets a caller frame a
//!   TCP stream without committing to a runtime. The one module that does
//!   touch a socket, [`net`], is a thin blocking driver kept separate from
//!   the codec.
//! * **Explicit endianness.** [`cursor::Reader`] / [`cursor::Writer`] make
//!   every big/little-endian access visible at the call site, because RDP
//!   mixes the two.
//! * **Total decoding.** Malformed input yields an [`Error`], never a panic.
//!
//! ## Example: build a Connection Request
//!
//! ```
//! use rusty_rdp::nego::{Negotiation, SecurityProtocols};
//! use rusty_rdp::tpkt::Tpkt;
//! use rusty_rdp::x224::X224;
//!
//! // Client asks for TLS or CredSSP.
//! let neg = Negotiation::Request {
//!     flags: 0,
//!     protocols: SecurityProtocols::SSL | SecurityProtocols::HYBRID,
//! };
//! let x224 = X224::connection_request(neg);
//! let tpdu = x224.to_vec().unwrap();
//! let packet = Tpkt::new(&tpdu).to_vec().unwrap();
//!
//! // `packet` is now ready to write to a TCP socket. Decode the round trip:
//! let tpkt = Tpkt::decode(&packet).unwrap();
//! assert_eq!(X224::decode(tpkt.payload).unwrap(), x224);
//! ```

pub mod ber;
pub mod capabilities;
pub mod clearcodec;
pub mod client_info;
pub mod cliprdr;
pub mod credssp;
pub mod crypto;
pub mod cursor;
pub mod display;
pub mod dvc;
pub mod dvcman;
pub mod error;
pub mod fastpath;
pub mod finalization;
pub mod gcc;
pub mod gfx;
pub mod input;
pub mod krb5;
pub mod license;
pub mod mcs;
pub mod nego;
pub mod net;
pub mod ntlm;
pub mod output;
pub mod pdu;
pub mod per;
pub mod pixel;
#[cfg(feature = "platform")]
pub mod platform_net;
pub mod planar;
pub mod pointer;
pub mod rdpdr;
pub mod rdpsnd;
pub mod rfx;
pub mod rle;
pub mod security;
#[cfg(feature = "tls")]
pub mod tls;
pub mod tpkt;
pub mod vchan;
pub mod x224;

pub use error::{Error, Result};

#[cfg(test)]
mod integration_tests {
    use crate::nego::{Negotiation, SecurityProtocols};
    use crate::tpkt::Tpkt;
    use crate::x224::X224;

    /// Full stack: encode a CR inside TPKT, then decode both layers back.
    #[test]
    fn tpkt_x224_nego_full_stack() {
        let neg = Negotiation::Request {
            flags: 0,
            protocols: SecurityProtocols::SSL,
        };
        let x224 = X224::connection_request(neg);
        let tpdu = x224.to_vec().unwrap();
        let packet = Tpkt::new(&tpdu).to_vec().unwrap();

        // Frame it as if arriving on a stream.
        assert_eq!(Tpkt::peek_total_len(&packet).unwrap(), Some(packet.len()));
        let tpkt = Tpkt::decode(&packet).unwrap();
        assert_eq!(X224::decode(tpkt.payload).unwrap(), x224);
    }

    /// After the X.224 handshake, RDP PDUs ride as MCS domain PDUs inside
    /// X.224 Data TPDUs inside TPKT. Exercise that whole nesting.
    #[test]
    fn mcs_send_data_over_x224_over_tpkt() {
        use crate::mcs::{DomainPdu, MCS_GLOBAL_CHANNEL_ID};

        let rdp_payload = [0x11, 0x22, 0x33, 0x44];
        let mcs = DomainPdu::SendDataRequest {
            initiator: 1007,
            channel_id: MCS_GLOBAL_CHANNEL_ID,
            user_data: &rdp_payload,
        };
        let mcs_bytes = mcs.to_vec().unwrap();
        let tpdu = X224::data(&mcs_bytes).to_vec().unwrap();
        let packet = Tpkt::new(&tpdu).to_vec().unwrap();

        // Peel the layers back off.
        let tpkt = Tpkt::decode(&packet).unwrap();
        let x224 = X224::decode(tpkt.payload).unwrap();
        let inner = match x224 {
            X224::Data(payload) => payload,
            other => panic!("expected Data TPDU, got {other:?}"),
        };
        assert_eq!(DomainPdu::decode(inner).unwrap(), mcs);
    }

    /// The client's MCS Connect-Initial: GCC settings blocks wrapped in a
    /// Conference Create Request, wrapped in Connect-Initial, wrapped in an
    /// X.224 Data TPDU, wrapped in TPKT. Build it and peel it fully back.
    #[test]
    fn connect_initial_full_stack() {
        use crate::gcc::{
            self, ClientCoreData, ClientSecurityData, UserDataBlock, ENCRYPTION_METHOD_128BIT,
        };
        use crate::mcs::ConnectInitial;

        let blocks = vec![
            UserDataBlock::ClientCore(ClientCoreData::new(1280, 800, "rusty-rdp")),
            UserDataBlock::ClientSecurity(ClientSecurityData {
                encryption_methods: ENCRYPTION_METHOD_128BIT,
                ext_encryption_methods: 0,
            }),
        ];

        // Build bottom-up.
        let user_data = gcc::encode_user_data(&blocks).unwrap();
        let ccr = gcc::encode_conference_create_request(&user_data).unwrap();
        let connect_initial = ConnectInitial::new(ccr).to_vec();
        let tpdu = X224::data(&connect_initial).to_vec().unwrap();
        let packet = Tpkt::new(&tpdu).to_vec().unwrap();

        // Peel top-down.
        let tpkt = Tpkt::decode(&packet).unwrap();
        let inner = match X224::decode(tpkt.payload).unwrap() {
            X224::Data(payload) => payload,
            other => panic!("expected Data TPDU, got {other:?}"),
        };
        let ci = ConnectInitial::decode(inner).unwrap();
        let gcc_blocks = gcc::decode_conference_create_request(&ci.user_data).unwrap();
        assert_eq!(gcc::parse_user_data(&gcc_blocks).unwrap(), blocks);
    }

    /// Standard-security commencement: encrypt a client random with the
    /// server's RSA key, ship it in a Security Exchange PDU over the wire
    /// stack, then derive matching keys on both ends and exchange one
    /// encrypted, MAC'd PDU.
    #[test]
    fn security_commencement_end_to_end() {
        use crate::mcs::{DomainPdu, MCS_GLOBAL_CHANNEL_ID};
        use crate::security::{
            self, derive_session_keys, Rc4Session, RsaPublicKey, SessionKeys, RANDOM_LEN,
        };

        // A tiny RSA key (n = 3233, e = 17) stands in for the server's; the
        // wire path is identical to a real 2048-bit key.
        let rsa = RsaPublicKey {
            modulus_le: vec![0xA1, 0x0C],
            exponent: 17,
        };
        let client_random = [0x5Au8; RANDOM_LEN];
        let server_random = [0xA5u8; RANDOM_LEN];

        // Client encrypts a one-byte "random" (small enough for the toy key)
        // and frames the Security Exchange PDU through MCS/X.224/TPKT.
        let encrypted = rsa.encrypt(&[42]).unwrap();
        let sec_pdu = security::encode_security_exchange(&encrypted);
        let mcs = DomainPdu::SendDataRequest {
            initiator: 1007,
            channel_id: MCS_GLOBAL_CHANNEL_ID,
            user_data: &sec_pdu,
        }
        .to_vec()
        .unwrap();
        let packet = Tpkt::new(&X224::data(&mcs).to_vec().unwrap())
            .to_vec()
            .unwrap();

        // Server peels the layers and recovers the Security Exchange payload.
        let tpkt = Tpkt::decode(&packet).unwrap();
        let X224::Data(x224_inner) = X224::decode(tpkt.payload).unwrap() else {
            panic!("expected Data TPDU");
        };
        let DomainPdu::SendDataRequest { user_data, .. } = DomainPdu::decode(x224_inner).unwrap()
        else {
            panic!("expected Send Data Request");
        };
        let recovered = security::decode_security_exchange(user_data).unwrap();
        assert_eq!(&recovered[..encrypted.len()], &encrypted[..]);

        // Both sides derive the (mirror-image) session keys and exchange one
        // encrypted, authenticated PDU.
        let client_keys = derive_session_keys(&client_random, &server_random, 0x02);
        let server_keys = SessionKeys {
            mac_key: client_keys.mac_key.clone(),
            encrypt_key: client_keys.decrypt_key.clone(),
            decrypt_key: client_keys.encrypt_key.clone(),
        };
        let mut client = Rc4Session::new(&client_keys);
        let mut server = Rc4Session::new(&server_keys);

        let (sig, ciphertext) = client.encrypt(b"TS_INFO_PACKET");
        assert_eq!(
            server.decrypt(&sig, &ciphertext).unwrap(),
            b"TS_INFO_PACKET"
        );
    }

    /// The Client Info PDU: encode logon info, MAC + RC4 it under a Basic
    /// Security Header, and confirm the server side recovers the credentials.
    #[test]
    fn client_info_encrypted_exchange() {
        use crate::client_info::ClientInfo;
        use crate::cursor::Writer;
        use crate::security::{
            derive_session_keys, BasicSecurityHeader, Rc4Session, SessionKeys, RANDOM_LEN,
            SEC_ENCRYPT, SEC_INFO_PKT,
        };

        let keys = derive_session_keys(&[7u8; RANDOM_LEN], &[9u8; RANDOM_LEN], 0x02);
        let server_keys = SessionKeys {
            mac_key: keys.mac_key.clone(),
            encrypt_key: keys.decrypt_key.clone(),
            decrypt_key: keys.encrypt_key.clone(),
        };
        let mut client = Rc4Session::new(&keys);
        let mut server = Rc4Session::new(&server_keys);

        // Client builds and encrypts the Client Info PDU.
        let info = ClientInfo::new("CORP", "alice", "s3cret");
        let (sig, ciphertext) = client.encrypt(&info.to_vec());
        let mut w = Writer::new();
        BasicSecurityHeader::new(SEC_INFO_PKT | SEC_ENCRYPT).encode(&mut w);
        w.write_bytes(&sig);
        w.write_bytes(&ciphertext);
        let pdu = w.into_vec();

        // Server splits header / signature / ciphertext and decrypts.
        let mut r = crate::cursor::Reader::new(&pdu);
        let header = BasicSecurityHeader::decode(&mut r).unwrap();
        assert!(header.flags & SEC_INFO_PKT != 0);
        let read_sig = r.read_bytes(8).unwrap();
        let recovered = server.decrypt(read_sig, r.peek_remaining()).unwrap();
        let decoded = ClientInfo::decode(&recovered).unwrap();
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.domain, "CORP");
    }

    /// Licensing: a server "no license needed" alert round-trips and is
    /// recognised as the go-ahead to capability exchange.
    #[test]
    fn licensing_valid_client_detected() {
        use crate::license::{LicenseErrorMessage, LicensePdu};

        let pdu = LicensePdu::ErrorAlert(LicenseErrorMessage::valid_client());
        let bytes = pdu.to_vec().unwrap();
        match LicensePdu::decode(&bytes).unwrap() {
            LicensePdu::ErrorAlert(msg) => assert!(msg.is_valid_client()),
            other => panic!("expected ErrorAlert, got {other:?}"),
        }
    }

    /// Capability exchange: the server's Demand Active advertises a bitmap
    /// capability, the client echoes the share id in a Confirm Active, and
    /// both PDUs travel the full MCS/X.224/TPKT stack.
    #[test]
    fn capability_exchange_over_wire() {
        use crate::capabilities::{
            client_capability_sets, BitmapCapabilitySet, CapabilitySet, ConfirmActive,
            DemandActive, GeneralCapabilitySet,
        };
        use crate::mcs::{DomainPdu, MCS_GLOBAL_CHANNEL_ID};

        // Helper: wrap RDP bytes as a server Send Data Indication over the wire.
        fn frame(payload: &[u8], indication: bool) -> Vec<u8> {
            let mcs = if indication {
                DomainPdu::SendDataIndication {
                    initiator: 1002,
                    channel_id: MCS_GLOBAL_CHANNEL_ID,
                    user_data: payload,
                }
            } else {
                DomainPdu::SendDataRequest {
                    initiator: 1007,
                    channel_id: MCS_GLOBAL_CHANNEL_ID,
                    user_data: payload,
                }
            };
            Tpkt::new(&X224::data(&mcs.to_vec().unwrap()).to_vec().unwrap())
                .to_vec()
                .unwrap()
        }
        fn unwrap_mcs(packet: &[u8]) -> Vec<u8> {
            let tpkt = Tpkt::decode(packet).unwrap();
            let X224::Data(inner) = X224::decode(tpkt.payload).unwrap() else {
                panic!("expected Data TPDU");
            };
            match DomainPdu::decode(inner).unwrap() {
                DomainPdu::SendDataIndication { user_data, .. }
                | DomainPdu::SendDataRequest { user_data, .. } => user_data.to_vec(),
                other => panic!("expected Send Data, got {other:?}"),
            }
        }

        // Server → client Demand Active.
        let demand = DemandActive {
            share_id: 0x0001_00EA,
            source_descriptor: b"RDP\0".to_vec(),
            capability_sets: vec![
                CapabilitySet::General(GeneralCapabilitySet::default()),
                CapabilitySet::Bitmap(BitmapCapabilitySet::new(1024, 768, 16)),
            ],
            session_id: 0,
        };
        let demand_packet = frame(&demand.encode(1002).unwrap(), true);
        let (_, recv_demand) = DemandActive::decode(&unwrap_mcs(&demand_packet)).unwrap();
        assert_eq!(recv_demand, demand);

        // Client → server Confirm Active echoing the share id.
        let confirm =
            ConfirmActive::new(recv_demand.share_id, client_capability_sets(1024, 768, 16));
        let confirm_packet = frame(&confirm.encode(1007).unwrap(), false);
        let (_, recv_confirm) = ConfirmActive::decode(&unwrap_mcs(&confirm_packet)).unwrap();
        assert_eq!(recv_confirm.share_id, demand.share_id);
        assert_eq!(recv_confirm, confirm);
    }

    /// Connection finalization: the client's four PDUs each round-trip as a
    /// Share Data PDU over the full MCS/X.224/TPKT stack, in order.
    #[test]
    fn finalization_sequence_over_wire() {
        use crate::finalization::{client_finalization_sequence, ControlPdu, FinalizationPdu};
        use crate::mcs::{DomainPdu, MCS_GLOBAL_CHANNEL_ID};

        let share_id = 0x0001_00EA;
        let seq = client_finalization_sequence(1002);

        let mut decoded = Vec::new();
        for pdu in seq {
            let rdp = pdu.encode(share_id, 1007).unwrap();
            let mcs = DomainPdu::SendDataRequest {
                initiator: 1007,
                channel_id: MCS_GLOBAL_CHANNEL_ID,
                user_data: &rdp,
            };
            let packet = Tpkt::new(&X224::data(&mcs.to_vec().unwrap()).to_vec().unwrap())
                .to_vec()
                .unwrap();

            // Peel TPKT → X.224 → MCS → Share Data → finalization PDU.
            let tpkt = Tpkt::decode(&packet).unwrap();
            let X224::Data(inner) = X224::decode(tpkt.payload).unwrap() else {
                panic!("expected Data TPDU");
            };
            let DomainPdu::SendDataRequest { user_data, .. } = DomainPdu::decode(inner).unwrap()
            else {
                panic!("expected Send Data Request");
            };
            let (_, sid, fin) = FinalizationPdu::decode(user_data).unwrap();
            assert_eq!(sid, share_id);
            assert_eq!(fin, pdu);
            decoded.push(fin);
        }

        // The order is Synchronize, Cooperate, Request Control, Font List.
        assert!(matches!(decoded[0], FinalizationPdu::Synchronize(_)));
        assert!(matches!(
            decoded[2],
            FinalizationPdu::Control(ControlPdu {
                action: crate::finalization::CTRLACTION_REQUEST_CONTROL,
                ..
            })
        ));
        assert!(matches!(decoded[3], FinalizationPdu::FontList(_)));
    }

    /// Input: a click-and-type burst travels as a single Input PDU over the
    /// full MCS/X.224/TPKT stack and decodes back to the same events.
    #[test]
    fn input_events_over_wire() {
        use crate::input::{InputEvent, InputPdu};
        use crate::mcs::{DomainPdu, MCS_GLOBAL_CHANNEL_ID};

        let share_id = 0x0001_00EA;
        let pdu = InputPdu::new(vec![
            InputEvent::mouse_move(320, 240),
            InputEvent::left_button_down(320, 240),
            InputEvent::left_button_up(320, 240),
            InputEvent::key_press(0x1E), // 'a'
            InputEvent::key_release(0x1E),
        ]);

        let rdp = pdu.encode(share_id, 1007).unwrap();
        let mcs = DomainPdu::SendDataRequest {
            initiator: 1007,
            channel_id: MCS_GLOBAL_CHANNEL_ID,
            user_data: &rdp,
        };
        let packet = Tpkt::new(&X224::data(&mcs.to_vec().unwrap()).to_vec().unwrap())
            .to_vec()
            .unwrap();

        let tpkt = Tpkt::decode(&packet).unwrap();
        let X224::Data(inner) = X224::decode(tpkt.payload).unwrap() else {
            panic!("expected Data TPDU");
        };
        let DomainPdu::SendDataRequest { user_data, .. } = DomainPdu::decode(inner).unwrap() else {
            panic!("expected Send Data Request");
        };
        let (_, sid, recovered) = InputPdu::decode(user_data).unwrap();
        assert_eq!(sid, share_id);
        assert_eq!(recovered, pdu);
    }

    /// Output: a server bitmap update travels as a Send Data Indication over
    /// the full stack and the client recovers the pixel rectangle.
    #[test]
    fn bitmap_update_over_wire() {
        use crate::mcs::{DomainPdu, MCS_GLOBAL_CHANNEL_ID};
        use crate::output::{BitmapData, UpdatePdu};

        let share_id = 0x0001_00EA;
        let pixels = vec![0x00, 0xF8, 0xE0, 0x07]; // two 16bpp pixels
        let update = UpdatePdu::Bitmap(vec![BitmapData::uncompressed(5, 7, 2, 1, 16, pixels)]);

        let rdp = update.encode(share_id, 1002).unwrap();
        let mcs = DomainPdu::SendDataIndication {
            initiator: 1002,
            channel_id: MCS_GLOBAL_CHANNEL_ID,
            user_data: &rdp,
        };
        let packet = Tpkt::new(&X224::data(&mcs.to_vec().unwrap()).to_vec().unwrap())
            .to_vec()
            .unwrap();

        let tpkt = Tpkt::decode(&packet).unwrap();
        let X224::Data(inner) = X224::decode(tpkt.payload).unwrap() else {
            panic!("expected Data TPDU");
        };
        let DomainPdu::SendDataIndication { user_data, .. } = DomainPdu::decode(inner).unwrap()
        else {
            panic!("expected Send Data Indication");
        };
        let (_, sid, recovered) = UpdatePdu::decode(user_data).unwrap();
        assert_eq!(sid, share_id);
        assert_eq!(recovered, update);
        if let UpdatePdu::Bitmap(rects) = recovered {
            assert_eq!(rects[0].dest_left, 5);
            assert_eq!(rects[0].width, 2);
        }
    }

    /// Capstone: a server RLE-compressed bitmap update travels the full wire
    /// stack, and the client decodes it to a top-down RGBA framebuffer.
    #[test]
    fn compressed_bitmap_to_rgba_over_wire() {
        use crate::mcs::{DomainPdu, MCS_GLOBAL_CHANNEL_ID};
        use crate::output::{BitmapData, UpdatePdu, BITMAP_COMPRESSION, NO_BITMAP_COMPRESSION_HDR};

        // A 2x2 16bpp rectangle, RLE-compressed (headerless):
        //   line 0 (bottom): colour run of red   (0xF800), 2 px
        //   line 1 (top):    colour run of green (0x07E0), 2 px
        // Colour run order 0x61 (len 1) but count needs 2 → use 0x62.
        let stream = vec![
            0x62, 0x00, 0xF8, // colour run, len 2, red (LE)
            0x62, 0xE0, 0x07, // colour run, len 2, green (LE)
        ];
        let rect = BitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: 1,
            dest_bottom: 1,
            width: 2,
            height: 2,
            bits_per_pixel: 16,
            flags: BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR,
            data: stream,
        };
        let update = UpdatePdu::Bitmap(vec![rect]);

        let rdp = update.encode(0x0001_00EA, 1002).unwrap();
        let mcs = DomainPdu::SendDataIndication {
            initiator: 1002,
            channel_id: MCS_GLOBAL_CHANNEL_ID,
            user_data: &rdp,
        };
        let packet = Tpkt::new(&X224::data(&mcs.to_vec().unwrap()).to_vec().unwrap())
            .to_vec()
            .unwrap();

        // Client: peel the layers, then decode the rectangle to RGBA.
        let tpkt = Tpkt::decode(&packet).unwrap();
        let X224::Data(inner) = X224::decode(tpkt.payload).unwrap() else {
            panic!("expected Data TPDU");
        };
        let DomainPdu::SendDataIndication { user_data, .. } = DomainPdu::decode(inner).unwrap()
        else {
            panic!("expected Send Data Indication");
        };
        let (_, _, decoded) = UpdatePdu::decode(user_data).unwrap();
        let UpdatePdu::Bitmap(rects) = decoded else {
            panic!("expected bitmap update");
        };
        let rgba = rects[0].to_rgba(None).unwrap();

        // Top-down RGBA: row 0 is the green line, row 1 the red line.
        assert_eq!(&rgba[0..4], &[0, 255, 0, 255]); // top-left green
        assert_eq!(&rgba[4..8], &[0, 255, 0, 255]); // top-right green
        assert_eq!(&rgba[8..12], &[255, 0, 0, 255]); // bottom-left red
        assert_eq!(&rgba[12..16], &[255, 0, 0, 255]); // bottom-right red
    }
}
