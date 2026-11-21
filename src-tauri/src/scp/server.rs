//! SCP server state machine — the PC side of `RealScpServer.handshakeInternal`
//! (SCP.md §3). Drives HELLO → SYNC → UKey2 → SYNC_SECURE on one TCP stream and
//! then keeps reading (and decrypting) whatever the phone sends next.

use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use super::ukey2::{Responder, SessionCipher, Ukey2Result};
use super::*;

/// How this PC presents itself in SYNC / SYNC_SECURE.
#[derive(Debug, Clone)]
pub struct LocalIdentity {
    pub device_id: String,
    pub device_name: String,
    pub model_id: String,
}

/// Outcome of a successful first-time pairing.
#[derive(Clone, Debug)]
pub struct Paired {
    pub peer_sync: Sync,
    pub peer_device_id: String,
    pub ksc: Vec<u8>,
    pub ksc_alias: Vec<u8>,
    pub ukey2: Ukey2Result,
}

const STEP_TIMEOUT: Duration = Duration::from_secs(15);

struct Conn<'a, S> {
    s: &'a mut S,
    version: u8,
    channel: String,
    namespace: String,
    cipher: Option<SessionCipher>,
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> Conn<'a, S> {
    fn header(&self, is_hello: bool) -> Header {
        Header {
            version: self.version,
            service_type: 0, // SYSTEM_SERVICE
            payload_type: PAYLOAD_PROTOBUF,
            encrypted: self.cipher.is_some(),
            is_server: true,
            struct_type: 0, // SCP_PROTOCOL
            payload_len: 0,
            next_header: 0,
            is_hello,
            crc_enabled: false,
            crc: 0,
            agent_address: agent_address(&self.channel, &self.namespace),
        }
    }

    async fn send(&mut self, msg_type: i32, data: Vec<u8>, is_hello: bool) -> anyhow::Result<()> {
        let pkt = ScpPacket { msg_type, data }.encode_to_vec();
        let payload = match &self.cipher {
            Some(c) => c.encrypt(&pkt)?,
            None => pkt,
        };
        let h = self.header(is_hello);
        println!("  → {} ({} bytes{})", msg_type::name(msg_type), payload.len(), if h.encrypted { ", encrypted" } else { "" });
        write_frame(self.s, h, &payload).await
    }

    async fn recv(&mut self) -> anyhow::Result<(Header, ScpPacket)> {
        let f = timeout(STEP_TIMEOUT, read_frame(self.s)).await??;
        let plain = if f.header.encrypted {
            let c = self.cipher.as_ref().ok_or_else(|| anyhow::anyhow!("encrypted frame before key exchange"))?;
            c.decrypt(&f.payload)?
        } else {
            f.payload.clone()
        };
        let pkt = ScpPacket::decode(plain.as_slice())?;
        println!(
            "  ← {} ({} bytes{})",
            msg_type::name(pkt.msg_type),
            f.payload.len(),
            if f.header.encrypted { ", encrypted" } else { "" }
        );
        if pkt.msg_type == msg_type::DISCONNECT {
            let d = Disconnect::decode(pkt.data.as_slice()).unwrap_or_default();
            anyhow::bail!("phone disconnected: code {} — {}", d.disconnect_code, d.disconnect_reason);
        }
        Ok((f.header, pkt))
    }

    async fn expect(&mut self, want: i32) -> anyhow::Result<(Header, ScpPacket)> {
        let (h, p) = self.recv().await?;
        anyhow::ensure!(p.msg_type == want, "expected {}, got {}", msg_type::name(want), msg_type::name(p.msg_type));
        Ok((h, p))
    }
}

/// Run the server side of one SCP connection.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, me: &LocalIdentity) -> anyhow::Result<Paired> {
    // 1. READ_HELLO
    let f = timeout(STEP_TIMEOUT, read_frame(s)).await??;
    let pkt = ScpPacket::decode(f.payload.as_slice())?;
    anyhow::ensure!(pkt.msg_type == msg_type::HELLO, "first packet was {}, not HELLO", msg_type::name(pkt.msg_type));
    let hello = Hello::decode(pkt.data.as_slice())?;
    println!("  ← HELLO seq {} channel {:?} namespace {:?} (SCP v{})", hello.sequence_no, hello.channel, hello.namespace, f.header.version);
    let mut c = Conn {
        s,
        version: f.header.version.min(SCP_VERSION),
        channel: hello.channel.clone(),
        namespace: hello.namespace.clone(),
        cipher: None,
    };

    // 2. WRITE_HELLO (seq + 1, same channel/namespace)
    let reply = Hello {
        sequence_no: hello.sequence_no.wrapping_add(1),
        channel: hello.channel.clone(),
        namespace: hello.namespace.clone(),
        service_name: String::new(),
    };
    c.send(msg_type::HELLO, reply.encode_to_vec(), true).await?;

    // 3. READ_SYNC
    let (_, p) = c.expect(msg_type::SYNC).await?;
    let peer_sync = Sync::decode(p.data.as_slice())?;
    println!(
        "     phone SYNC: name {:?} keyType {} deviceType {} trigger {} model {:?} link {} custom {} bytes",
        peer_sync.device_name, peer_sync.key_type, peer_sync.device_type, peer_sync.active_trigger_mode,
        peer_sync.model_id, peer_sync.link_type, peer_sync.custom_data.len()
    );

    // 4. WRITE_SYNC — we only speak UKEY2 (keyType 1).
    let my_sync = Sync {
        device_name: me.device_name.clone(),
        key_type: 1,
        custom_data: Vec::new(),
        device_type: 6, // PC
        active_trigger_mode: peer_sync.active_trigger_mode,
        model_id: me.model_id.clone(),
        link_type: peer_sync.link_type,
    };
    c.send(msg_type::SYNC, my_sync.encode_to_vec(), false).await?;

    // 5-6. UKey2
    let (_, p) = c.expect(msg_type::UKEY2_INIT).await?;
    let (responder, server_init) = Responder::new(&p.data)?;
    c.send(msg_type::UKEY2_INIT, server_init, false).await?;
    let (_, p) = c.expect(msg_type::UKEY2_FINISHED).await?;
    let ukey2 = responder.finish(&p.data)?;
    println!("     UKey2 complete — verification code {}", hex::encode(&ukey2.auth_string[..4]));
    c.send(msg_type::UKEY2_FINISHED, Vec::new(), false).await?;
    c.cipher = Some(SessionCipher::new(&ukey2));

    // 7-8. SYNC_SECURE (encrypted from here on)
    let (_, p) = c.expect(msg_type::SYNC_SECURE).await?;
    let peer = SyncSecure::decode(p.data.as_slice())?;
    println!(
        "     phone SYNC_SECURE: deviceId {:?}, KSC {} bytes, alias {} bytes",
        peer.device_id, peer.ksc.len(), peer.ksc_alias.len()
    );
    let mine = SyncSecure { device_id: me.device_id.clone(), ksc: peer.ksc.clone(), ksc_alias: peer.ksc_alias.clone() };
    c.send(msg_type::SYNC_SECURE, mine.encode_to_vec(), false).await?;

    Ok(Paired { peer_sync, peer_device_id: peer.device_id, ksc: peer.ksc, ksc_alias: peer.ksc_alias, ukey2 })
}

/// After the handshake: log every further frame (decrypting when flagged)
/// and answer the phone's INTERACT stage: the phone sends raw "interact
/// hello" (or "reconnect interact hello") and waits up to 21 s for a raw
/// `PairAction` string; anything but "accept" makes it fail with 2517
/// "rejected by server" (MixServiceSmartNetworking). `allow` is the user's
/// decision (see `approval`): "accept", or "reject" and hang up.
pub async fn observe<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    cipher: Option<SessionCipher>,
    peer_ip: Option<std::net::IpAddr>,
    secs: u64,
    allow: bool,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let f = match tokio::time::timeout_at(deadline, read_frame(s)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                println!("  (connection ended: {e})");
                return;
            }
            Err(_) => {
                println!("  (observe window over)");
                return;
            }
        };
        let plain = match (&cipher, f.header.encrypted) {
            (Some(c), true) => c.decrypt(&f.payload).unwrap_or_else(|e| {
                println!("  ! {e}");
                f.payload.clone()
            }),
            _ => f.payload.clone(),
        };
        println!(
            "  ← frame: serviceType {} structType {} encrypted {} len {} extraHdr {}",
            f.header.service_type, f.header.struct_type, f.header.encrypted, f.payload.len(), hex::encode(&f.extra_headers)
        );
        match ScpPacket::decode(plain.as_slice()) {
            Ok(p) if f.header.struct_type == 0 => {
                println!("     SCP {} data {}", msg_type::name(p.msg_type), hex::encode(&p.data))
            }
            _ if crate::util::debug() => println!("     raw {}  {:?}", hex::encode(&plain), String::from_utf8_lossy(&plain)),
            _ => println!("     raw {} bytes", plain.len()),
        }
        println!("     header {:?}", f.header);

        if f.header.struct_type == 1 && (plain == b"interact hello" || plain == b"reconnect interact hello") {
            let reply: &[u8] = if allow { b"accept" } else { b"reject" };
            let payload = match (&cipher, f.header.encrypted) {
                (Some(c), true) => match c.encrypt(reply) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("  ! encrypt: {e}");
                        return;
                    }
                },
                _ => reply.to_vec(),
            };
            let mut h = f.header.clone();
            h.is_server = true;
            h.is_hello = false;
            h.next_header = 0;
            h.crc_enabled = false;
            h.crc = 0;
            println!("  → raw {:?} ({} bytes)", String::from_utf8_lossy(reply), payload.len());
            if let Err(e) = write_frame(s, h, &payload).await {
                println!("  ! write: {e}");
                return;
            }
            if !allow {
                return;
            }
            if let Some(ip) = peer_ip {
                tokio::spawn(backward_probe(ip));
            }
        }
    }
}

/// TCP port the phone listens on after INTERACT, waiting ~2 s for the PC to
/// connect back (`CloudProbeConnection`, "backward probe"). No data is
/// exchanged: the connect alone proves the Wi-Fi path works both ways.
pub const PROBE_PORT: u16 = 10153;

async fn backward_probe(ip: std::net::IpAddr) {
    let addr = std::net::SocketAddr::new(ip, PROBE_PORT);
    for attempt in 1..=20 {
        match timeout(Duration::from_millis(500), tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(sock)) => {
                println!("  → backward probe connected to {addr} (attempt {attempt})");
                // Hold it open briefly in case the phone reads from it.
                tokio::time::sleep(Duration::from_secs(10)).await;
                drop(sock);
                return;
            }
            Ok(Err(e)) if attempt == 20 => println!("  ! backward probe to {addr} failed: {e}"),
            Err(_) if attempt == 20 => println!("  ! backward probe to {addr} timed out"),
            _ => tokio::time::sleep(Duration::from_millis(150)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ukey2::Initiator;
    use super::*;

    /// A fake phone that follows the phone's client flow (`RealScpClient`).
    async fn fake_phone<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, device_id: &str) -> anyhow::Result<(Vec<u8>, SessionCipher)> {
        let (ch, ns) = ("active_connection", "com.heytap.accessory");
        let hdr = |enc: bool, hello: bool| Header {
            version: 4, service_type: 0, payload_type: 3, encrypted: enc, is_server: false, struct_type: 0,
            payload_len: 0, next_header: 0, is_hello: hello, crc_enabled: false, crc: 0, agent_address: agent_address(ch, ns),
        };
        let send = |t: i32, d: Vec<u8>| ScpPacket { msg_type: t, data: d }.encode_to_vec();
        let hello = Hello { sequence_no: -5, channel: ch.into(), namespace: ns.into(), service_name: String::new() };
        write_frame(s, hdr(false, true), &send(msg_type::HELLO, hello.encode_to_vec())).await?;
        let r = read_frame(s).await?;
        assert!(r.header.is_server && r.header.is_hello);
        let h = Hello::decode(ScpPacket::decode(r.payload.as_slice())?.data.as_slice())?;
        assert_eq!(h.sequence_no, -4);

        let sync = Sync { device_name: "Phone".into(), key_type: 1, device_type: 8, active_trigger_mode: 1, link_type: 1, ..Default::default() };
        write_frame(s, hdr(false, false), &send(msg_type::SYNC, sync.encode_to_vec())).await?;
        let r = read_frame(s).await?;
        let their = Sync::decode(ScpPacket::decode(r.payload.as_slice())?.data.as_slice())?;
        assert_eq!(their.device_type, 6);

        let (init, ci) = Initiator::new();
        write_frame(s, hdr(false, false), &send(msg_type::UKEY2_INIT, ci)).await?;
        let r = read_frame(s).await?;
        let si = ScpPacket::decode(r.payload.as_slice())?;
        let (cf, keys) = init.finish(&si.data)?;
        write_frame(s, hdr(false, false), &send(msg_type::UKEY2_FINISHED, cf)).await?;
        let r = read_frame(s).await?;
        assert_eq!(ScpPacket::decode(r.payload.as_slice())?.msg_type, msg_type::UKEY2_FINISHED);

        let cipher = SessionCipher::new(&keys);
        let ss = SyncSecure { device_id: device_id.into(), ksc: vec![7; 32], ksc_alias: vec![9; 8] };
        let ct = cipher.encrypt(&send(msg_type::SYNC_SECURE, ss.encode_to_vec()))?;
        write_frame(s, hdr(true, false), &ct).await?;
        let r = read_frame(s).await?;
        assert!(r.header.encrypted);
        let back = SyncSecure::decode(ScpPacket::decode(cipher.decrypt(&r.payload)?.as_slice())?.data.as_slice())?;
        assert_eq!(back.ksc, vec![7; 32]);
        Ok((back.ksc, cipher))
    }

    #[tokio::test]
    async fn full_handshake_against_fake_phone() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let me = LocalIdentity { device_id: "4C494E555801".into(), device_name: "Linux".into(), model_id: "B5339A".into() };
        let (server, phone) = tokio::join!(accept(&mut a, &me), fake_phone(&mut b, "A1B2C3D4E5F6"));
        let paired = server.unwrap();
        assert_eq!(phone.unwrap().0, paired.ksc);
        assert_eq!(paired.peer_device_id, "A1B2C3D4E5F6");
    }

    /// Against the running app (`npm run tauri dev`): a rogue "phone" that
    /// completes the pairing handshake but isn't approved must get "reject",
    /// and nothing may be saved. Leave the dialog alone while it runs (20 s).
    #[tokio::test]
    #[ignore = "needs the app running; cargo test -- --ignored live_"]
    async fn live_unapproved_pairing_is_rejected() {
        let id = "AABBCCDDEEF0";
        let file = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap().join(format!(".local/share/olink/pairing-{id}.json"));
        let _ = std::fs::remove_file(&file);
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", SCP_PORT)).await.unwrap();
        let (_, cipher) = fake_phone(&mut s, id).await.unwrap();
        let hdr = Header {
            version: 4, service_type: 0, payload_type: 3, encrypted: true, is_server: false, struct_type: 1,
            payload_len: 0, next_header: 0, is_hello: false, crc_enabled: false, crc: 0, agent_address: [0; 4],
        };
        write_frame(&mut s, hdr, &cipher.encrypt(b"interact hello").unwrap()).await.unwrap();
        let f = tokio::time::timeout(Duration::from_secs(40), read_frame(&mut s)).await.expect("an answer").unwrap();
        assert_eq!(cipher.decrypt(&f.payload).unwrap(), b"reject");
        assert!(!file.exists(), "an unapproved pairing was saved");
    }
}
