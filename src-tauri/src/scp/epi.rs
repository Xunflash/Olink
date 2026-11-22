//! "EPI" / PD (peer descriptor) exchange: the first thing on the data channel
//! the phone opens to the QR's `addr` (TCP 46888) after SCP + INTERACT + probe.
//!
//! Recovered from the phone's `vd/b.java` (compose/parse), `vd/i.java`
//! (feature params), `le/d.java` + `h4/b.java` (Wi-Fi framing) and
//! `EpiClientFsm` (the phone is the client and waits for the server to send
//! an OFFER (type 1) or PROBE (type 3) first; it replies ANSWER (2) / PROBE
//! ANSWER (4) and gives up after ~10 s: "Failed to exchange PD").
//!
//! Wire framing (CRC off by default): `[len: u16 BE][payload]`.
//!
//! OFFER/ANSWER payload (all big-endian):
//! ```text
//! u8  MessageType        1 = offer, 2 = answer
//! u16 ProtocolVersion    10 (if > 10: + AccountHash[32] PeerDeviceId[6] AccountStatus u8)
//! [36] PeerId            ASCII, exactly 36 bytes (UUID-shaped)
//! u8  SapLayerModes      (TLMode << 4) | CLMode
//! u8  featureParamsCount, then per param: u8 key + value
//!       1 APDUSize u32 · 2 SSDUSize u16 · 3 MaxSessions u16 · 4 SLTimeout u16
//!       5 TLWindowSize u16 · 6 ProductId (u8 len + str) · 7 ManufacturerId (u8 len + str)
//!       8 FriendlyName (u8 len + str) · 10 DevCategory u8 · 11 CompressionBit u8
//!       12 ServiceProfileCount u8 · 13 DynamicConnection u8 · 14 wifi MAC [6] · 15 NFC u8
//! ```
//! All feature params are optional (the parser fills defaults).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MSG_OFFER: u8 = 1;
pub const MSG_ANSWER: u8 = 2;
pub const MSG_PROBE: u8 = 3;
pub const MSG_PROBE_ANSWER: u8 = 4;

/// Build our OFFER payload (without the length prefix).
pub fn build_offer(peer_id: &str, friendly_name: &str) -> Vec<u8> {
    let mut pid = peer_id.as_bytes().to_vec();
    pid.resize(36, b'0');
    let name = &friendly_name.as_bytes()[..friendly_name.len().min(64)];

    let mut b = vec![MSG_OFFER];
    b.extend_from_slice(&10u16.to_be_bytes()); // ProtocolVersion
    b.extend_from_slice(&pid);
    b.push((2 << 4) | 0); // TLMode 2, CLMode 0 (the phone's own Wi-Fi defaults)
    b.push(2); // featureParamsCount
    b.push(8); // FriendlyName
    b.push(name.len() as u8);
    b.extend_from_slice(name);
    b.push(10); // DevCategory
    b.push(6); // PC
    b
}

pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> anyhow::Result<()> {
    let mut buf = u16::try_from(payload.len())?.to_be_bytes().to_vec();
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let mut p = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut p).await?;
    Ok(p)
}

/// Human-readable dump of an OFFER/ANSWER (best effort).
pub fn describe(p: &[u8]) -> String {
    if p.len() < 40 || !(p[0] == MSG_OFFER || p[0] == MSG_ANSWER) {
        return format!("type {:?} ({} bytes)", p.first(), p.len());
    }
    let ver = u16::from_be_bytes([p[1], p[2]]);
    let mut i = 3;
    let mut s = format!("{} v{ver}", if p[0] == MSG_ANSWER { "ANSWER" } else { "OFFER" });
    if ver > 10 && p.len() >= i + 39 {
        s += &format!(" accountHash {} peerDeviceId {} accStatus {}", hex::encode(&p[i..i + 32]), hex::encode(&p[i + 32..i + 38]), p[i + 38]);
        i += 39;
    }
    if p.len() < i + 38 {
        return s;
    }
    s += &format!(" peerId {:?}", String::from_utf8_lossy(&p[i..i + 36]));
    i += 36;
    s += &format!(" modes 0x{:02x}", p[i]);
    i += 1;
    s += &format!(" features[{}] {}", p[i], hex::encode(&p[i + 1..]));
    s
}

// ---------------------------------------------------------------------------
// KSC authentication (right after the PD exchange). `datatrans/security/b.java`
// `f(int, …)`. The phone (client) sends AUTH_REQUEST, we (server) answer
// AUTH_RESPONSE, the phone sends AUTH_CONFIRM. MAC = HMAC-SHA512(KSC, …)[..8],
// with times serialised **little-endian** inside the MAC but big-endian on the
// wire. KSC = the raw 16-byte key from SCP SYNC_SECURE.
//
//   0x10 REQUEST  (38): type, ver=2, qc[8], tc u64, mac=H(qc‖tc)[8], deviceId[6], kscAlias[6]
//   0x11 RESPONSE (27): type, ver=2, status=0, qs[8], ts u64, Rs=H(qc‖qs‖ts)[0..8]
//   0x12 CONFIRM  (11): type, ver=2, status=0, Rc2=H(qs‖tc)[8]
// H(qc‖qs‖ts)[8..16] becomes the session key.

pub const AUTH_REQUEST: u8 = 0x10;
pub const AUTH_RESPONSE: u8 = 0x11;
pub const AUTH_CONFIRM: u8 = 0x12;

fn hmac8(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    let mut m = <Hmac<sha2::Sha512> as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub qc: [u8; 8],
    pub tc: u64,
    pub mac: [u8; 8],
    pub device_id: [u8; 6],
    pub ksc_alias: [u8; 6],
}

pub fn parse_auth_request(p: &[u8]) -> anyhow::Result<AuthRequest> {
    anyhow::ensure!(p.len() >= 38 && p[0] == AUTH_REQUEST, "not an AUTH_REQUEST");
    Ok(AuthRequest {
        qc: p[2..10].try_into()?,
        tc: u64::from_be_bytes(p[10..18].try_into()?),
        mac: p[18..26].try_into()?,
        device_id: p[26..32].try_into()?,
        ksc_alias: p[32..38].try_into()?,
    })
}

pub fn check_auth_request(ksc: &[u8], r: &AuthRequest) -> bool {
    hmac8(ksc, &[&r.qc, &r.tc.to_le_bytes()])[..8] == r.mac
}

/// Returns (RESPONSE payload, expected CONFIRM mac, session key).
pub fn build_auth_response(ksc: &[u8], r: &AuthRequest, qs: [u8; 8], ts: u64) -> (Vec<u8>, [u8; 8], [u8; 8]) {
    let h = hmac8(ksc, &[&r.qc, &qs, &ts.to_le_bytes()]);
    let mut b = vec![AUTH_RESPONSE, 2, 0];
    b.extend_from_slice(&qs);
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&h[..8]);
    let confirm: [u8; 8] = hmac8(ksc, &[&qs, &r.tc.to_le_bytes()])[..8].try_into().unwrap();
    (b, confirm, h[8..16].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Session-layer frames (after auth). `discovery/bleprovider/advertise/i.java z()`:
// a 2-byte header follows the length prefix (the length covers header + body):
//   byte0 = (ctrl << 4 & 0x10) | (sessionId >> 6 & 0x0f)
//   byte1 = (fragMode & 3) | ((sessionId & 63) << 2)      fragMode 0 = whole
// (+2-byte seq number only on TL-mode-2 sessions of type 5; not CapEx.)
// CapEx ("capability exchange") runs on reserved session 2. The phone, as
// client, waits for the server's sync query first (`datatrans/a.java t()`).

pub const CAPEX_SESSION: u16 = 2;

pub fn session_frame(session: u16, body: &[u8]) -> Vec<u8> {
    let mut b = vec![((session >> 6) & 0x0f) as u8, (((session & 63) << 2) & 0xfc) as u8];
    b.extend_from_slice(body);
    b
}

/// (sessionId, ctrl bit, fragMode, body)
pub fn parse_session_frame(p: &[u8]) -> Option<(u16, u8, u8, &[u8])> {
    if p.len() < 2 {
        return None;
    }
    let sid = (((p[0] & 0x0f) as u16) << 6) | ((p[1] >> 2) as u16);
    Some((sid, (p[0] >> 4) & 1, p[1] & 3, &p[2..]))
}

/// CapEx sync query: type 1, queryType 3, u32 0, count, then "profileId;"...
pub fn capex_sync_query(profiles: &[&str]) -> Vec<u8> {
    let mut b = vec![1, 3, 0, 0, 0, 0, profiles.len() as u8];
    for p in profiles {
        b.extend_from_slice(p.as_bytes());
        b.push(b';');
    }
    b
}

/// CapEx response: type 2, queryType, u32 (queryType 2|3), u16 recordCount,
/// then per record: "profileId;" "name;" u16 nChannels, per channel:
/// u16 id, "name;", u16, u8, u16  (`service/i.java y()`). Empty for now.
pub fn capex_empty_response(query_type: u8) -> Vec<u8> {
    let mut b = vec![2, query_type];
    if query_type == 2 || query_type == 3 {
        b.extend_from_slice(&[0, 0, 0, 0]);
    }
    b.extend_from_slice(&[0, 0]);
    b
}

/// One service agent we advertise in CapEx.
pub struct Agent<'a> {
    pub agent_id: u16,
    pub profile_id: &'a str,
    pub version: u16, // major << 8 | minor
    pub role: u8,     // low 2 bits; 0 = provider (the phone's consumers look for these)
    pub conn_timeout: u16,
}

/// CapEx response carrying one app record (`service/i.java` parser ~l.340):
/// "appName;" "str2;" u16 nAgents, per agent: u16 agentId, "profileId;",
/// u16 version, u8 role, u16 connTimeOut.
pub fn capex_response(query_type: u8, app: &str, app2: &str, agents: &[Agent]) -> Vec<u8> {
    let mut b = vec![2, query_type];
    if query_type == 2 || query_type == 3 {
        b.extend_from_slice(&[0, 0, 0, 0]); // mChecksum
    }
    if agents.is_empty() {
        b.extend_from_slice(&[0, 0]);
        return b;
    }
    b.extend_from_slice(&1u16.to_be_bytes()); // mNoOfRecords
    b.extend_from_slice(app.as_bytes());
    b.push(b';');
    b.extend_from_slice(app2.as_bytes());
    b.push(b';');
    b.extend_from_slice(&(agents.len() as u16).to_be_bytes());
    for a in agents {
        b.extend_from_slice(&a.agent_id.to_be_bytes());
        b.extend_from_slice(a.profile_id.as_bytes());
        b.push(b';');
        b.extend_from_slice(&a.version.to_be_bytes());
        b.push(a.role & 3);
        b.extend_from_slice(&a.conn_timeout.to_be_bytes());
    }
    b
}

/// App/container name in our CapEx record. Must NOT be "com.oplus.linker":
/// the phone's `ICDFAgentSelector.getHighSpeedAgent` skips agents from its
/// own package, which silently disables clipboard ("highPeerAgent is null").
pub const OUR_APP_NAME: &str = "com.oplus.connect.linux";

/// What we offer right now.
pub const CLIPBOARD_AGENT_ID: u16 = 4101;
pub const DISCOVERY_AGENT_ID: u16 = 4102;
pub const FILE_AGENT_ID: u16 = 4103;
/// OPPO Share's Windows channel. When a PC connects (as consumer) to the
/// phone's provider, OShare adds the PC to its share sheet ("pc_device_mac").
pub const OSHARE_WIN_AGENT_ID: u16 = 4104;
pub const OSHARE_WIN_PROFILE: &str = "app:oshare.win.agent";
pub fn our_agents() -> Vec<Agent<'static>> {
    vec![
        Agent { agent_id: CLIPBOARD_AGENT_ID, profile_id: "app:clipboardservice", version: 0x0100, role: 0, conn_timeout: 10 },
        Agent { agent_id: DISCOVERY_AGENT_ID, profile_id: "com.oplus.pantaconnect.globaldevice.discovery", version: 0x0100, role: 0, conn_timeout: 10 },
        Agent { agent_id: FILE_AGENT_ID, profile_id: "app:fileservice", version: 0x0100, role: 0, conn_timeout: 10 },
        Agent { agent_id: OSHARE_WIN_AGENT_ID, profile_id: OSHARE_WIN_PROFILE, version: 0x0100, role: 1, conn_timeout: 10 },
    ]
}

/// Profile IDs listed in a CapEx query body (after type, queryType[, u32], count).
pub fn capex_query_profiles(body: &[u8]) -> Vec<String> {
    if body.len() < 3 {
        return vec![];
    }
    let start = if body[1] == 2 || body[1] == 3 { 7 } else { 3 };
    if body.len() <= start {
        return vec![];
    }
    String::from_utf8_lossy(&body[start..]).split(';').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// Our agents answering a query: all of them for an empty query, else the matches.
pub fn agents_for_query(body: &[u8]) -> Vec<Agent<'static>> {
    let want = capex_query_profiles(body);
    our_agents().into_iter().filter(|a| want.is_empty() || want.iter().any(|w| w == a.profile_id)).collect()
}

// ---------------------------------------------------------------------------
// Service connection (reserved session 1; `session/a.java` parser,
// `mm/c.java Q()` composer). Agent ids are (remote, local) from the SENDER's view.
//   REQUEST  01 u16 remote u16 local "profile;" u16 n, n×u16 sessionId,
//            n×u16 channelId, n×(u8 qosType u8 qosClass), n×u8 payloadType
//   RESPONSE 02 u16 remote u16 local "profile;" u8 status u16 n, n×u16 sessionId
//   03 = timeout/cancel by requester ("profile;" only)

pub const SERVICE_SESSION: u16 = 1;

#[derive(Debug, Clone)]
pub struct ServiceConnRequest {
    pub remote_agent: u16, // ours
    pub local_agent: u16,  // the phone's
    pub profile: String,
    pub sessions: Vec<u16>,
    pub channels: Vec<u16>,
}

pub fn parse_service_conn_request(b: &[u8]) -> anyhow::Result<ServiceConnRequest> {
    anyhow::ensure!(b.len() > 6 && b[0] == 1, "not a service connection request");
    let remote_agent = u16::from_be_bytes([b[1], b[2]]);
    let local_agent = u16::from_be_bytes([b[3], b[4]]);
    let semi = b[5..].iter().position(|&c| c == b';').ok_or_else(|| anyhow::anyhow!("no ';'"))? + 5;
    let profile = String::from_utf8_lossy(&b[5..semi]).to_string();
    let mut i = semi + 1;
    let rd = |i: usize| -> anyhow::Result<u16> { Ok(u16::from_be_bytes(b.get(i..i + 2).ok_or_else(|| anyhow::anyhow!("short"))?.try_into()?)) };
    let n = rd(i)? as usize;
    i += 2;
    let mut sessions = vec![];
    for _ in 0..n {
        sessions.push(rd(i)?);
        i += 2;
    }
    let mut channels = vec![];
    for _ in 0..n {
        channels.push(rd(i)?);
        i += 2;
    }
    Ok(ServiceConnRequest { remote_agent, local_agent, profile, sessions, channels })
}

/// Answer to the phone's AGENT AUTHENTICATE request (type 5: 05 remote local "profile;"):
/// type 6 with "cert type 1, no certificate", which the phone treats as
/// "trusted with no certificate" (`session/a.java` case 6). OShare's
/// WinProviderAgent accepts on any authentication response.
pub fn agent_auth_response(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 6 || req[0] != 5 {
        return None;
    }
    let semi = req.iter().position(|&c| c == b';')?;
    let mut b = vec![6];
    b.extend_from_slice(&req[3..5]); // remote (from our view) = the phone's agent = its "local"
    b.extend_from_slice(&req[1..3]); // local = ours
    b.extend_from_slice(&req[5..=semi]);
    b.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
    Some(b)
}

pub fn service_conn_response(req: &ServiceConnRequest, status: u8) -> Vec<u8> {
    let mut b = vec![2];
    b.extend_from_slice(&req.local_agent.to_be_bytes()); // remote (= phone) from our view
    b.extend_from_slice(&req.remote_agent.to_be_bytes()); // local (= us)
    b.extend_from_slice(req.profile.as_bytes());
    b.push(b';');
    b.push(status);
    b.extend_from_slice(&(req.sessions.len() as u16).to_be_bytes());
    for s in &req.sessions {
        b.extend_from_slice(&s.to_be_bytes());
    }
    b
}

// ---------------------------------------------------------------------------
// Per-session app cipher (`fe/b.java`, `fe/a.java`), keyed after KSC auth.
// Encrypted payload = t (u64 BE counter) ‖ AES-128-GCM(ciphertext ‖ tag).
// h = HMAC-SHA512(KSC, qc ‖ qs ‖ t_BE): key = h[0..16], nonce = h[16..28],
// AAD = h[28..48]. Each direction counts its own t up from 1.

pub struct AppCipher {
    ksc: Vec<u8>,
    qcqs: [u8; 16],
    send_t: u64,
    /// Highest counter accepted from the phone, and which of the 64 below it
    /// were seen: the phone sometimes sends a little out of order, but a
    /// counter is never accepted twice, so recorded messages can't be replayed.
    recv_t: u64,
    recv_seen: u64,
}

impl AppCipher {
    pub fn new(ksc: &[u8], qc: [u8; 8], qs: [u8; 8]) -> Self {
        let mut qcqs = [0u8; 16];
        qcqs[..8].copy_from_slice(&qc);
        qcqs[8..].copy_from_slice(&qs);
        Self { ksc: ksc.to_vec(), qcqs, send_t: 0, recv_t: 0, recv_seen: 0 }
    }

    /// Same keys, fresh counters (each session has its own cipher state).
    pub fn fresh(&self) -> Self {
        Self { ksc: self.ksc.clone(), qcqs: self.qcqs, send_t: 0, recv_t: 0, recv_seen: 0 }
    }

    fn material(&self, t: u64) -> [u8; 64] {
        hmac8(&self.ksc, &[&self.qcqs, &t.to_be_bytes()])
    }

    pub fn decrypt(&mut self, data: &[u8]) -> anyhow::Result<(u64, Vec<u8>)> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        anyhow::ensure!(data.len() >= 8 + 16, "too short");
        let t = u64::from_be_bytes(data[..8].try_into()?);
        let fresh = t > self.recv_t || {
            let back = self.recv_t - t;
            back < 64 && self.recv_seen & (1u64 << back) == 0
        };
        anyhow::ensure!(t > 0 && fresh, "replayed or too-late message (counter {t}, newest {})", self.recv_t);
        let h = self.material(t);
        let c = aes_gcm::Aes128Gcm::new_from_slice(&h[..16])?;
        let pt = c
            .decrypt(aes_gcm::Nonce::from_slice(&h[16..28]), Payload { msg: &data[8..], aad: &h[28..48] })
            .map_err(|_| anyhow::anyhow!("GCM tag mismatch"))?;
        if t > self.recv_t {
            let shift = t - self.recv_t;
            self.recv_seen = if shift >= 64 { 0 } else { self.recv_seen << shift };
            self.recv_seen |= 1;
            self.recv_t = t;
        } else {
            self.recv_seen |= 1u64 << (self.recv_t - t);
        }
        Ok((t, pt))
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        self.send_t += 1;
        let h = self.material(self.send_t);
        let c = aes_gcm::Aes128Gcm::new_from_slice(&h[..16])?;
        let ct = c
            .encrypt(aes_gcm::Nonce::from_slice(&h[16..28]), Payload { msg: plain, aad: &h[28..48] })
            .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
        let mut out = self.send_t.to_be_bytes().to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made-up pairing key and nonces (the real captures stay private).
    const KSC: [u8; 16] = [0x11; 16];
    const QC: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const QS: [u8; 8] = [9, 10, 11, 12, 13, 14, 15, 16];

    /// An AUTH_REQUEST laid out like the phone's: type, ver, qc, tc, mac, deviceId, alias.
    fn auth_request(ksc: &[u8], qc: [u8; 8], tc: u64) -> Vec<u8> {
        let mut b = vec![AUTH_REQUEST, 2];
        b.extend_from_slice(&qc);
        b.extend_from_slice(&tc.to_be_bytes());
        b.extend_from_slice(&hmac8(ksc, &[&qc, &tc.to_le_bytes()])[..8]);
        b.extend_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        b.extend_from_slice(&[0x5e; 6]);
        b
    }

    /// A DataBus (session 8) frame: our cipher's output decrypts, once.
    #[test]
    fn databus_frame_roundtrip_and_no_replay() {
        let mut tx = AppCipher::new(&KSC, QC, QS);
        let mut body = vec![4, 0, 1];
        body.extend_from_slice(&tx.encrypt(b"{\"mPayLoadType\":1}").unwrap());
        let m = session_frame(8, &body);
        let (sid, _, _, body) = parse_session_frame(&m).unwrap();
        assert_eq!(sid, 8);
        let mut rx = AppCipher::new(&KSC, QC, QS);
        let (t, pt) = rx.decrypt(&body[3..]).unwrap();
        assert_eq!((t, pt.as_slice()), (1, &b"{\"mPayLoadType\":1}"[..]));
        // The same message again is a replay.
        assert!(rx.decrypt(&body[3..]).is_err());
        // A wrong key fails the tag check.
        assert!(AppCipher::new(&[0x22; 16], QC, QS).decrypt(&body[3..]).is_err());
    }

    #[test]
    fn parses_real_service_connection_request() {
        let b = hex::decode("011005b3696170703a636c6970626f617264736572766963653b000200d400b80068006e050104010000").unwrap();
        let r = parse_service_conn_request(&b).unwrap();
        assert_eq!((r.remote_agent, r.local_agent), (4101, 45929));
        assert_eq!(r.profile, "app:clipboardservice");
        assert_eq!(r.sessions, vec![212, 184]);
        assert_eq!(r.channels, vec![104, 110]);
        assert_eq!(hex::encode(service_conn_response(&r, 0)), "02b36910056170703a636c6970626f617264736572766963653b00000200d400b8");
    }

    /// The phone may send a little out of order; a counter still only counts once.
    #[test]
    fn reordering_window() {
        let mut tx = AppCipher::new(&KSC, QC, QS);
        let msgs: Vec<Vec<u8>> = (0..4).map(|i| tx.encrypt(&[i]).unwrap()).collect(); // counters 1..=4
        let mut rx = AppCipher::new(&KSC, QC, QS);
        assert!(rx.decrypt(&msgs[1]).is_ok()); // 2
        assert!(rx.decrypt(&msgs[0]).is_ok()); // 1, late but new
        assert!(rx.decrypt(&msgs[0]).is_err()); // 1 again: replay
        assert!(rx.decrypt(&msgs[3]).is_ok()); // 4
        assert!(rx.decrypt(&msgs[2]).is_ok()); // 3, late but new
        assert!(rx.decrypt(&msgs[3]).is_err()); // 4 again
    }

    /// Per-session ciphers count separately: two sessions both start at 1.
    #[test]
    fn session_ciphers_are_independent() {
        let base = AppCipher::new(&KSC, QC, QS);
        let (mut a, mut b) = (base.fresh(), base.fresh());
        let (ca, cb) = (a.encrypt(b"one").unwrap(), b.encrypt(b"two").unwrap());
        let mut rx = base.fresh();
        assert_eq!(rx.decrypt(&ca).unwrap(), (1, b"one".to_vec()));
        assert_eq!(base.fresh().decrypt(&cb).unwrap(), (1, b"two".to_vec()));
    }

    #[test]
    fn agent_auth_answer() {
        // Real type-5 request from the phone (2026-11-19).
        let req = hex::decode("0510089b566170703a6f73686172652e77696e2e6167656e743b").unwrap();
        assert_eq!(
            hex::encode(agent_auth_response(&req).unwrap()),
            "069b5610086170703a6f73686172652e77696e2e6167656e743b01010000"
        );
    }

    #[test]
    fn session_header_roundtrip() {
        let f = session_frame(2, &[9]);
        assert_eq!(&f[..2], &[0x00, 0x08]);
        assert_eq!(parse_session_frame(&f), Some((2, 0, 0, &[9u8][..])));
        let f = session_frame(1000, &[]);
        assert_eq!(parse_session_frame(&f).unwrap().0, 1000);
    }

    #[test]
    fn verifies_auth_request() {
        let r = parse_auth_request(&auth_request(&KSC, QC, 1806490)).unwrap();
        assert_eq!(r.tc, 1806490);
        assert!(check_auth_request(&KSC, &r));
        assert!(!check_auth_request(&[0u8; 16], &r));
        let (resp, _, _) = build_auth_response(&KSC, &r, [1; 8], 5);
        assert_eq!(resp.len(), 27);
    }

    #[test]
    fn offer_layout() {
        let o = build_offer("4C494E555801-0000-0000-0000-000000000000", "Linux");
        assert_eq!(o[0], 1);
        assert_eq!(&o[1..3], &[0, 10]);
        assert_eq!(o.len(), 3 + 36 + 1 + 1 + 2 + 5 + 2);
        assert!(o.len() >= 41, "phone requires >= 41 bytes");
        assert!(describe(&o).contains("Linux") || describe(&o).contains("4c696e7578"));
    }
}
