//! ODMF screen-cast signalling (phone → PC WebRTC), first experiment.
//!
//! The PC tells the phone to cast by publishing `rsp_odmf_key` on the DataBus
//! topic `Oplus_Cast` (see CAST.md). That carries our signalling server's
//! `server_ip`/`port` and an `odmf_auth_info` credential we generate here. The
//! phone (`OdmfSocketClient`) then TCP-connects to us; frames are
//! `[u16 BE length][payload]`, payload JSON (or, once authenticated, possibly
//! `[0x01][13-byte ms timestamp][12-byte IV][AES-GCM]`).
//!
//! Server side, mirroring `odmfr/odmfh.java` + `odmfr/odmfe.java`:
//!   → `{"cmd":"OdmfAuthRequest","auth_version":1}`
//!   ← `{"cmd":"OdmfAuthResponse","auth_info":"{timestamp,iv,public_key,encrypt_cipher}",…}`
//!     verify AES-GCM(ECDH(our key, phone key), iv, aad=timestamp)(…) == id
//!   → `{"cmd":"AuthSuccess",timestamp,iv,encrypt_cipher=GCM({"id","key"}),auth_version:1}`
//!   ← `PairRequest` → `PairSuccess`; `ping` → `pong`; `send` = peer message
//!     (`offer`, `candidate`, …) which this experiment only logs.
//!
//! OPPO's server is a rendezvous relay pairing two clients; we play the PC's
//! peer ourselves.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey, ECDH_P256};
use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Fixed so the phone (connecting in) can pass the firewall.
pub const SIGNAL_PORT: u16 = 46892;

/// The credential we hand the phone in `rsp_odmf_key` (`AuthUtils` format).
pub struct AuthInfo {
    pub id: [u8; 8],
    /// Reusable P-256 key (aws-lc-rs, constant-time): the video and audio
    /// channels each run the ECDH with it.
    secret: PrivateKey,
    /// AES-256 session key we give the phone in AuthSuccess.
    pub session_key: [u8; 32],
    pub timestamp: u64,
}

impl AuthInfo {
    pub fn generate() -> Self {
        Self {
            id: rand::random(),
            secret: PrivateKey::generate(&ECDH_P256).expect("P-256 keygen"),
            session_key: rand::random(),
            timestamp: now_ms(),
        }
    }

    /// `odmf_auth_info`: `{"id","public_key"(X.509 SPKI),"timestamp","auth_version":1}`.
    pub fn json(&self) -> anyhow::Result<String> {
        let pk = self.secret.compute_public_key().map_err(|_| anyhow::anyhow!("P-256 public key failed"))?;
        let spki: PublicKeyX509Der = pk.as_der().map_err(|_| anyhow::anyhow!("SPKI encoding failed"))?;
        Ok(json!({
            "id": B64.encode(self.id),
            "public_key": B64.encode(spki.as_ref()),
            "timestamp": self.timestamp.to_string(),
            "auth_version": 1,
        })
        .to_string())
    }

    /// ECDH with the phone's X.509 public key → raw 32-byte x-coordinate,
    /// which ODMF uses directly as the AES-256 key (Java `KeyAgreement`).
    fn shared_key(&self, phone_spki_b64: &str) -> anyhow::Result<[u8; 32]> {
        // X.509 SPKI, parsed and checked to be a P-256 point by aws-lc-rs.
        let spki = B64.decode(phone_spki_b64)?;
        agree(&self.secret, &UnparsedPublicKey::new(&ECDH_P256, &spki), anyhow::anyhow!("ECDH with the phone's key failed"), |z| {
            z.try_into().map_err(|_| anyhow::anyhow!("unexpected shared-secret length"))
        })
    }
}

/// The `rsp_odmf_key` publish for topic `Oplus_Cast` (`CastDbsReceiver`):
/// `{"key":"cast_ability_sync","value":"<CastMessage JSON>"}`.
///
/// `app` (a package name, e.g. `com.instagram.android`) casts just that app:
/// the phone opens it on a separate virtual display ("mirage" cast,
/// `CastSceneManager` → `MirageSceneImpl.startMirageCast`) and the phone's own
/// screen stays free. `None` mirrors the whole screen.
pub fn rsp_odmf_key_payload(auth: &AuthInfo, server_ip: &str, client_id: i64, app: Option<&str>) -> anyhow::Result<String> {
    let mut params = json!({
        "port": SIGNAL_PORT,
        "odmf_auth_info": auth.json()?,
        "clientId": client_id,
        "server_ip": server_ip,
        "privacyProtect": false,
    });
    if let Some(app) = app {
        params["component_name"] = json!(app);
    }
    let msg = json!({
        "msg_type": 0,
        "msg_cmd": "rsp_odmf_key",
        "msg_body": params.to_string(),
        "msg_value": 0,
        "clientId": client_id,
    });
    Ok(json!({"key": "cast_ability_sync", "value": msg.to_string()}).to_string())
}

/// The `pcAbility` publish for topic `Oplus_MacConnect` (linker `MacDbsReceiver`
/// → `MacSceneManager.dealwithPcAbility`). The phone stores these as device
/// properties; Settings → Device connect → PC shows "Screencast" only when
/// `CastAbility` ≥ 1000 (or `PCVersion` ≥ 3.1.0 for a Windows PC, type 6).
/// Every field read with `getString` must be present or the whole message is
/// dropped.
pub fn pc_ability_payload() -> String {
    let ability = json!({
        "PCVersion": "3.1.0",
        "CastAbility": "1000",
        "GameCastAbility": "0",
        "Synergy_CastUnlock_Version": "0",
        "crossdeviceClipboardVersion": "1200",
        "Notice_ClipBoard": "1",
        "Notice_CrossDevice": "1",
        "Notice_MaterialFlow": "1",
        "Synergy_CastUnlock_Mode": "0",
        "ScreenShareAbility": "0",
        "ScreenShareArrange": "0",
        "OSType": "Linux",
        "OSVersion": "",
    });
    json!({"key": "pcAbility", "value": ability.to_string()}).to_string()
}

/// Codec the PC asks for (`OdmfUtils.convertStrToVideoCodec`: H264, H264_HIGH,
/// H264_BASELINE, H265, VP8, VP9). H.264 High: hardware-decodable here.
pub const PC_CODEC: &str = "H264_HIGH";

/// `{"type":"pc_codec","codec":…,"sdk_version":…}`: lets the phone create its offer.
fn pc_codec_msg() -> Value {
    json!({"type": "pc_codec", "codec": PC_CODEC, "sdk_version": "2.8.0"})
}

/// Peer messages travel as `{"cmd":"send","msg":"<JSON string>"}`.
fn peer_msg(inner: &Value) -> Value {
    json!({"cmd": "send", "msg": inner.to_string()})
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn gcm_encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> anyhow::Result<([u8; 12], Vec<u8>)> {
    let iv: [u8; 12] = rand::random();
    let ct = Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad })
        .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;
    Ok((iv, ct))
}

fn gcm_decrypt(key: &[u8; 32], iv: &[u8], aad: &[u8], ct: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(iv.len() == 12, "IV must be 12 bytes, got {}", iv.len());
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(iv), Payload { msg: ct, aad })
        .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed (wrong key/IV/AAD)"))
}

/// Encrypted ODMF frame: `[0x01][13-byte timestamp][12-byte IV][ct]`, session key.
fn decrypt_frame(session_key: &[u8; 32], b: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(b.len() > 1 + 13 + 12 && b[0] == 1, "not an encrypted frame");
    gcm_decrypt(session_key, &b[14..26], &b[1..14], &b[26..])
}

fn encrypt_frame(session_key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let ts = now_ms().to_string();
    anyhow::ensure!(ts.len() == 13, "timestamp is not 13 digits");
    let (iv, ct) = gcm_encrypt(session_key, ts.as_bytes(), plaintext)?;
    let mut out = vec![1u8];
    out.extend_from_slice(ts.as_bytes());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

async fn read_frame(s: &mut tokio::net::TcpStream) -> anyhow::Result<Vec<u8>> {
    let n = s.read_u16().await? as usize;
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(b)
}

async fn write_frame(s: &mut tokio::net::TcpStream, b: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(b.len() <= u16::MAX as usize, "frame too large");
    s.write_u16(b.len() as u16).await?;
    s.write_all(b).await?;
    s.flush().await?;
    Ok(())
}

/// The credential and phone the running server accepts (replaced on re-pair).
static CURRENT: std::sync::Mutex<Option<(std::sync::Arc<AuthInfo>, std::net::IpAddr)>> = std::sync::Mutex::new(None);
static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Start the signalling server (once per run); only `phone` may connect. A
/// later call (the phone reconnected/re-paired) just swaps in the new
/// credential, since port 46892 is already ours.
pub async fn start(auth: std::sync::Arc<AuthInfo>, phone: std::net::IpAddr, log_dir: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    *CURRENT.lock().unwrap() = Some((auth, phone));
    if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        println!("  ★ ODMF signalling server already running; using the new credential (phone {phone})");
        return Ok(());
    }
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", SIGNAL_PORT)).await {
        Ok(l) => l,
        Err(e) => {
            STARTED.store(false, std::sync::atomic::Ordering::SeqCst);
            return Err(e.into());
        }
    };
    println!("  ★ ODMF signalling server on TCP {SIGNAL_PORT} (phone {phone} only)");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, from)) = listener.accept().await else { break };
            let Some((auth, phone)) = CURRENT.lock().unwrap().clone() else { continue };
            if from.ip() != phone {
                println!("  ! odmf: refusing connection from {from}");
                continue;
            }
            println!("  ★ ODMF: phone connected from {from}");
            let log_dir = log_dir.clone();
            tokio::spawn(async move {
                if let Err(e) = session(&mut s, &auth, &log_dir).await {
                    println!("  ! ODMF session: {e:#}");
                }
                println!("  ODMF: phone disconnected");
            });
        }
    });
    Ok(())
}

async fn session(s: &mut tokio::net::TcpStream, auth: &AuthInfo, log_dir: &Option<std::path::PathBuf>) -> anyhow::Result<()> {
    let (mut rd, mut wr) = s.split();
    // Frames from the phone, read in their own future (read_exact isn't cancel-safe).
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<anyhow::Result<Vec<u8>>>();
    // Peer messages (offer, candidates) produced by the WebRTC receiver.
    let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let reader = async move {
        loop {
            let r = async {
                let n = rd.read_u16().await? as usize;
                let mut b = vec![0u8; n];
                rd.read_exact(&mut b).await?;
                anyhow::Ok(b)
            }
            .await;
            let stop = r.is_err();
            if frame_tx.send(r).is_err() || stop {
                break;
            }
        }
    };
    let main = async move {
        let req = json!({"cmd": "OdmfAuthRequest", "auth_version": 1}).to_string();
        write_half(&mut wr, req.as_bytes()).await?;
        println!("  → odmf {req}");
        let mut authed = false;
        let mut peer_encrypts = false;
        let mut media = super::castrx::Media::Video;
        let mut receiver: Option<super::castrx::Receiver> = None;
        loop {
            let (cmd, replies): (String, Vec<Value>) = tokio::select! {
                Some(m) = peer_rx.recv() => ("<peer>".into(), vec![peer_msg(&m)]),
                f = tokio::time::timeout(std::time::Duration::from_secs(60), frame_rx.recv()) => {
                    let raw = match f {
                        Ok(Some(r)) => r?,
                        Ok(None) => return anyhow::Ok(()),
                        Err(_) => anyhow::bail!("phone silent for 60 s"),
                    };
                    let text = if raw.first() == Some(&1) {
                        peer_encrypts = true;
                        match decrypt_frame(&auth.session_key, &raw) {
                            Ok(p) => String::from_utf8_lossy(&p).to_string(),
                            Err(e) => {
                                println!("  ! odmf: encrypted frame ({} bytes) failed: {e:#}", raw.len());
                                continue;
                            }
                        }
                    } else {
                        String::from_utf8_lossy(&raw).to_string()
                    };
                    let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                    let cmd = v["cmd"].as_str().unwrap_or_default().to_string();
                    if cmd != "ping" {
                        if crate::util::debug() {
                            println!("  ← odmf {}", text.chars().take(600).collect::<String>());
                        } else {
                            println!("  ← odmf {cmd}");
                        }
                    }
                    let mut replies = vec![];
                    match cmd.as_str() {
                        "OdmfAuthResponse" => {
                            let info: Value = serde_json::from_str(v["auth_info"].as_str().unwrap_or("{}"))?;
                            let ts = info["timestamp"].as_str().unwrap_or_default();
                            let key = auth.shared_key(info["public_key"].as_str().unwrap_or_default())?;
                            let id = gcm_decrypt(
                                &key,
                                &B64.decode(info["iv"].as_str().unwrap_or_default())?,
                                ts.as_bytes(),
                                &B64.decode(info["encrypt_cipher"].as_str().unwrap_or_default())?,
                            );
                            match id {
                                Ok(id) if id == auth.id => {
                                    media = super::castrx::Media::from_transport_bus_id(v["local_transportbus_id"].as_str().unwrap_or_default());
                                    println!("  ★ ODMF: phone proved the shared key (id matches) — {media:?} channel");
                                    let ts2 = now_ms().to_string();
                                    let inner = json!({"id": B64.encode(auth.id), "key": B64.encode(auth.session_key)}).to_string();
                                    let (iv, ct) = gcm_encrypt(&key, ts2.as_bytes(), inner.as_bytes())?;
                                    authed = true;
                                    replies.push(json!({"cmd": "AuthSuccess", "timestamp": ts2, "iv": B64.encode(iv), "encrypt_cipher": B64.encode(ct), "auth_version": 1}));
                                }
                                other => {
                                    println!("  ! ODMF: phone auth failed: {:?}", other.map(hex::encode));
                                    write_half(&mut wr, json!({"cmd": "AuthFail"}).to_string().as_bytes()).await?;
                                    anyhow::bail!("auth failed");
                                }
                            }
                        }
                        _ if !authed => println!("  ! odmf: {cmd:?} before auth; ignoring"),
                        "ping" => replies.push(json!({"cmd": "pong"})),
                        "PairRequest" => {
                            replies.push(json!({
                                "cmd": "PairSuccess",
                                "remote_user_id": "linux",
                                "remote_user_name": crate::settings::pc_name(),
                                "remote_transportbus_id": v["remote_transportbus_id"].as_str().filter(|s| !s.is_empty()).unwrap_or("linux-peer"),
                            }));
                            // PC cast waits for the PC's codec (odmfu/odmfb "waiting for pc codec").
                            if media == super::castrx::Media::Video {
                                replies.push(peer_msg(&pc_codec_msg()));
                            }
                            // The phone is the answerer (isHost: false): we offer.
                            match super::castrx::Receiver::start(media, peer_tx.clone()) {
                                Ok(r) => receiver = Some(r),
                                Err(e) => println!("  ! WebRTC receiver: {e:#}"),
                            }
                        }
                        "send" => {
                            let msg: Value = v["msg"].as_str().and_then(|m| serde_json::from_str(m).ok()).unwrap_or(v["msg"].clone());
                            println!("  ★ ODMF peer message type {:?}", msg["type"].as_str().unwrap_or_default());
                            log_peer(log_dir, "in", &msg);
                            if let Some(r) = receiver.as_ref() {
                                r.on_peer_message(&msg);
                            }
                        }
                        _ => {}
                    }
                    (cmd, replies)
                }
            };
            for r in replies {
                let body = r.to_string();
                if cmd == "<peer>" {
                    log_peer(log_dir, "out", &r);
                }
                // Auth messages stay plain; mirror the phone once it encrypts.
                let wire = if peer_encrypts && cmd != "OdmfAuthResponse" { encrypt_frame(&auth.session_key, body.as_bytes())? } else { body.clone().into_bytes() };
                write_half(&mut wr, &wire).await?;
                if cmd != "ping" && crate::util::debug() {
                    println!("  → odmf {}", body.chars().take(300).collect::<String>());
                }
            }
        }
    };
    tokio::select! {
        r = main => r,
        _ = reader => Ok(()),
    }
}

async fn write_half(w: &mut (impl AsyncWriteExt + Unpin), b: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(b.len() <= u16::MAX as usize, "frame too large");
    w.write_u16(b.len() as u16).await?;
    w.write_all(b).await?;
    w.flush().await?;
    Ok(())
}

/// Debug only: append a peer message (both directions) to
/// `odmf-peer-messages.jsonl` in the private runtime dir.
fn log_peer(dir: &Option<std::path::PathBuf>, dir_label: &str, msg: &Value) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(dir) = dir else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(dir.join("odmf-peer-messages.jsonl")) {
        let _ = writeln!(f, "{dir_label} {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Play the phone's side (`AuthUtils.generateAuthInfoFromJson` +
    /// `SigIdentityAuthHelper.getAuthInfo`) against our credential.
    #[test]
    fn phone_side_auth_roundtrip() {
        let ours = AuthInfo::generate();
        let info: Value = serde_json::from_str(&ours.json().unwrap()).unwrap();
        // Phone: parse our key, make its own, ECDH.
        let our_spki = B64.decode(info["public_key"].as_str().unwrap()).unwrap();
        let phone = PrivateKey::generate(&ECDH_P256).unwrap();
        let k_phone: [u8; 32] = agree(&phone, &UnparsedPublicKey::new(&ECDH_P256, &our_spki), (), |z| Ok(z.try_into().unwrap())).unwrap();
        let phone_der: PublicKeyX509Der = phone.compute_public_key().unwrap().as_der().unwrap();
        let phone_spki = B64.encode(phone_der.as_ref());
        // Server derives the same key from the phone's public key.
        assert_eq!(ours.shared_key(&phone_spki).unwrap(), k_phone);
        // Phone encrypts id with aad = timestamp; we decrypt it.
        let ts = "1795100000000";
        let (iv, ct) = gcm_encrypt(&k_phone, ts.as_bytes(), &ours.id).unwrap();
        assert_eq!(gcm_decrypt(&k_phone, &iv, ts.as_bytes(), &ct).unwrap(), ours.id);
        assert!(gcm_decrypt(&k_phone, &iv, b"1795100000001", &ct).is_err());
    }

    #[test]
    fn encrypted_frame_roundtrip() {
        let k: [u8; 32] = rand::random();
        let f = encrypt_frame(&k, b"{\"cmd\":\"pong\"}").unwrap();
        assert_eq!(f[0], 1);
        assert_eq!(decrypt_frame(&k, &f).unwrap(), b"{\"cmd\":\"pong\"}");
    }

    #[test]
    fn rsp_payload_shape() {
        let a = AuthInfo::generate();
        let p: Value = serde_json::from_str(&rsp_odmf_key_payload(&a, "192.168.1.2", 1, None).unwrap()).unwrap();
        assert_eq!(p["key"], "cast_ability_sync");
        let m: Value = serde_json::from_str(p["value"].as_str().unwrap()).unwrap();
        assert_eq!(m["msg_cmd"], "rsp_odmf_key");
        let body: Value = serde_json::from_str(m["msg_body"].as_str().unwrap()).unwrap();
        assert_eq!(body["port"], SIGNAL_PORT);
        assert!(body["odmf_auth_info"].as_str().unwrap().contains("public_key"));
    }
}
