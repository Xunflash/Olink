//! UKey2 (cipher P256_SHA512) exactly as the phone's vendored
//! `com.google.security.cryptauth.lib.securegcm.Ukey2Handshake` runs it — stock
//! Google UKey2 plus OPPO's one addition: a 16-byte random `ivSpec` in
//! ClientFinished, used as the AES-GCM IV of the session (see SCP.md §4-5).
//!
//! Built from standard, well-reviewed primitives: P-256 ECDH from `aws-lc-rs`
//! (constant-time, the library rustls uses), RustCrypto `hkdf`, `sha2`,
//! `aes-gcm`. The protocol logic is small; no crypto primitive is hand-rolled.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aws_lc_rs::agreement::{agree_ephemeral, EphemeralPrivateKey, ParsedPublicKey, UnparsedPublicKey, ECDH_P256};
use hkdf::Hkdf;
use prost::Message;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

pub const CIPHER_P256_SHA512: i32 = 100;
pub const NEXT_PROTOCOL: &str = "AES_256_CBC-HMAC_SHA256";

pub mod ukey2_type {
    pub const ALERT: i32 = 1;
    pub const CLIENT_INIT: i32 = 2;
    pub const SERVER_INIT: i32 = 3;
    pub const CLIENT_FINISH: i32 = 4;
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2Message {
    #[prost(int32, tag = "1")]
    pub message_type: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub message_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CipherCommitment {
    #[prost(int32, tag = "1")]
    pub handshake_cipher: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub commitment: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ClientInit {
    #[prost(int32, tag = "1")]
    pub version: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub random: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    pub cipher_commitments: Vec<CipherCommitment>,
    #[prost(string, tag = "4")]
    pub next_protocol: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ServerInit {
    #[prost(int32, tag = "1")]
    pub version: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub random: Vec<u8>,
    #[prost(int32, tag = "3")]
    pub handshake_cipher: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub public_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ClientFinished {
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: Vec<u8>,
    /// OPPO addition (`IVSPEC_FIELD_NUMBER = 2`).
    #[prost(bytes = "vec", tag = "2")]
    pub iv_spec: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Alert {
    #[prost(int32, tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub error_message: String,
}

// securemessage.GenericPublicKey { type=1 (EC_P256=1); ec_p256_public_key=2 { x=1; y=2 } }
#[derive(Clone, PartialEq, Message)]
pub struct EcP256PublicKey {
    #[prost(bytes = "vec", tag = "1")]
    pub x: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub y: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GenericPublicKey {
    #[prost(int32, tag = "1")]
    pub r#type: i32,
    #[prost(message, optional, tag = "2")]
    pub ec_p256_public_key: Option<EcP256PublicKey>,
}

/// Java `BigInteger.toByteArray()` style: big-endian two's complement, i.e. a
/// leading 0x00 when the top bit is set.
fn to_java_bigint(b: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = {
        let i = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
        &b[i..]
    };
    let mut v = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(trimmed);
    v
}

fn from_java_bigint(b: &[u8]) -> anyhow::Result<[u8; 32]> {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    let s = &b[i..];
    anyhow::ensure!(s.len() <= 32, "EC coordinate too long ({} bytes)", s.len());
    let mut out = [0u8; 32];
    out[32 - s.len()..].copy_from_slice(s);
    Ok(out)
}

/// A fresh ephemeral P-256 key and its uncompressed point (0x04 ‖ x ‖ y).
fn new_key() -> anyhow::Result<(EphemeralPrivateKey, Vec<u8>)> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let k = EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| anyhow::anyhow!("P-256 keygen failed"))?;
    let point = k.compute_public_key().map_err(|_| anyhow::anyhow!("P-256 public key failed"))?.as_ref().to_vec();
    anyhow::ensure!(point.len() == 65 && point[0] == 4, "unexpected P-256 point encoding");
    Ok((k, point))
}

/// GenericPublicKey from an uncompressed P-256 point (0x04 ‖ x ‖ y).
pub fn encode_public_key(point: &[u8]) -> Vec<u8> {
    GenericPublicKey {
        r#type: 1,
        ec_p256_public_key: Some(EcP256PublicKey { x: to_java_bigint(&point[1..33]), y: to_java_bigint(&point[33..65]) }),
    }
    .encode_to_vec()
}

/// GenericPublicKey → uncompressed point, checked to be on P-256.
pub fn decode_public_key(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let g = GenericPublicKey::decode(bytes)?;
    anyhow::ensure!(g.r#type == 1, "public key type {} is not EC_P256", g.r#type);
    let ec = g.ec_p256_public_key.ok_or_else(|| anyhow::anyhow!("missing ec_p256_public_key"))?;
    let mut point = vec![4u8];
    point.extend_from_slice(&from_java_bigint(&ec.x)?);
    point.extend_from_slice(&from_java_bigint(&ec.y)?);
    ParsedPublicKey::try_from(&UnparsedPublicKey::new(&ECDH_P256, &point))
        .map_err(|_| anyhow::anyhow!("peer public key is not on P-256"))?;
    Ok(point)
}

/// ECDH with our ephemeral key → raw 32-byte shared x-coordinate.
fn ecdh(secret: EphemeralPrivateKey, peer_point: &[u8]) -> anyhow::Result<Vec<u8>> {
    agree_ephemeral(secret, &UnparsedPublicKey::new(&ECDH_P256, peer_point), anyhow::anyhow!("ECDH failed"), |z| Ok(z.to_vec()))
}

/// Single-block HKDF-SHA256 (matches the phone's `i2.a.a(key, salt, info)`).
fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out).expect("32 <= 255*32");
    out
}

/// What a completed handshake yields.
#[derive(Clone)]
pub struct Ukey2Result {
    /// HKDF(derived, "UKEY2 v1 auth", transcript) — the verification string.
    pub auth_string: [u8; 32],
    /// HKDF(derived, "UKEY2 v1 next", transcript).
    pub next_secret: [u8; 32],
    /// D2D "client" key — the AES-256-GCM session key used in BOTH directions.
    pub session_key: [u8; 32],
    /// First 12 bytes of the client's ivSpec — the (fixed) GCM nonce.
    pub session_iv: [u8; 12],
}

impl std::fmt::Debug for Ukey2Result {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ukey2Result { <secret> }")
    }
}

fn derive(z: &[u8], client_init_msg: &[u8], server_init_msg: &[u8], iv_spec: &[u8]) -> anyhow::Result<Ukey2Result> {
    anyhow::ensure!(iv_spec.len() >= 12, "ivSpec too short ({} bytes)", iv_spec.len());
    let derived = Sha256::digest(z);
    let mut transcript = client_init_msg.to_vec();
    transcript.extend_from_slice(server_init_msg);
    let auth_string = hkdf32(&derived, b"UKEY2 v1 auth", &transcript);
    let next_secret = hkdf32(&derived, b"UKEY2 v1 next", &transcript);
    let d2d_salt = Sha256::digest(b"D2D");
    let session_key = hkdf32(&next_secret, &d2d_salt, b"client");
    let mut session_iv = [0u8; 12];
    session_iv.copy_from_slice(&iv_spec[..12]);
    Ok(Ukey2Result { auth_string, next_secret, session_key, session_iv })
}

/// UKey2 responder (the PC / SCP server side).
pub struct Responder {
    secret: EphemeralPrivateKey,
    client_init_msg: Vec<u8>,
    server_init_msg: Vec<u8>,
    commitment: Vec<u8>,
}

impl Responder {
    /// Consume the client's Ukey2Message(ClientInit); return Ukey2Message(ServerInit).
    pub fn new(client_init_msg: &[u8]) -> anyhow::Result<(Self, Vec<u8>)> {
        let m = Ukey2Message::decode(client_init_msg)?;
        anyhow::ensure!(m.message_type == ukey2_type::CLIENT_INIT, "expected CLIENT_INIT, got type {}", m.message_type);
        let ci = ClientInit::decode(m.message_data.as_slice())?;
        anyhow::ensure!(ci.version == 1, "unsupported UKey2 version {}", ci.version);
        anyhow::ensure!(ci.random.len() == 32, "ClientInit random must be 32 bytes");
        let commitment = ci
            .cipher_commitments
            .iter()
            .find(|c| c.handshake_cipher == CIPHER_P256_SHA512)
            .ok_or_else(|| anyhow::anyhow!("client offered no P256_SHA512 commitment"))?
            .commitment
            .clone();
        if ci.next_protocol != NEXT_PROTOCOL {
            tracing::warn!(next_protocol = %ci.next_protocol, "unexpected UKey2 next_protocol");
        }

        let (secret, point) = new_key()?;
        let mut random = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let si = ServerInit {
            version: 1,
            random,
            handshake_cipher: CIPHER_P256_SHA512,
            public_key: encode_public_key(&point),
        };
        let server_init_msg = Ukey2Message {
            message_type: ukey2_type::SERVER_INIT,
            message_data: si.encode_to_vec(),
        }
        .encode_to_vec();
        Ok((
            Self { secret, client_init_msg: client_init_msg.to_vec(), server_init_msg: server_init_msg.clone(), commitment },
            server_init_msg,
        ))
    }

    /// Consume Ukey2Message(ClientFinished); verify the commitment; derive keys.
    pub fn finish(self, client_finished_msg: &[u8]) -> anyhow::Result<Ukey2Result> {
        anyhow::ensure!(
            Sha512::digest(client_finished_msg).as_slice() == self.commitment.as_slice(),
            "ClientFinished does not match the ClientInit commitment"
        );
        let m = Ukey2Message::decode(client_finished_msg)?;
        anyhow::ensure!(m.message_type == ukey2_type::CLIENT_FINISH, "expected CLIENT_FINISH, got type {}", m.message_type);
        let cf = ClientFinished::decode(m.message_data.as_slice())?;
        let peer = decode_public_key(&cf.public_key)?;
        let z = ecdh(self.secret, &peer)?;
        derive(&z, &self.client_init_msg, &self.server_init_msg, &cf.iv_spec)
    }
}

/// UKey2 initiator — mirrors the phone. Used only to test the responder.
pub struct Initiator {
    secret: EphemeralPrivateKey,
    client_init_msg: Vec<u8>,
    client_finished_msg: Vec<u8>,
    iv_spec: Vec<u8>,
}

impl Initiator {
    pub fn new() -> (Self, Vec<u8>) {
        let (secret, point) = new_key().expect("keygen");
        let mut iv_spec = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv_spec);
        let client_finished_msg = Ukey2Message {
            message_type: ukey2_type::CLIENT_FINISH,
            message_data: ClientFinished { public_key: encode_public_key(&point), iv_spec: iv_spec.clone() }
                .encode_to_vec(),
        }
        .encode_to_vec();
        let mut random = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let ci = ClientInit {
            version: 1,
            random,
            cipher_commitments: vec![CipherCommitment {
                handshake_cipher: CIPHER_P256_SHA512,
                commitment: Sha512::digest(&client_finished_msg).to_vec(),
            }],
            next_protocol: NEXT_PROTOCOL.into(),
        };
        let client_init_msg =
            Ukey2Message { message_type: ukey2_type::CLIENT_INIT, message_data: ci.encode_to_vec() }.encode_to_vec();
        (Self { secret, client_init_msg: client_init_msg.clone(), client_finished_msg, iv_spec }, client_init_msg)
    }

    /// Consume ServerInit; return (ClientFinished message, derived keys).
    pub fn finish(self, server_init_msg: &[u8]) -> anyhow::Result<(Vec<u8>, Ukey2Result)> {
        let m = Ukey2Message::decode(server_init_msg)?;
        anyhow::ensure!(m.message_type == ukey2_type::SERVER_INIT, "expected SERVER_INIT");
        let si = ServerInit::decode(m.message_data.as_slice())?;
        let peer = decode_public_key(&si.public_key)?;
        let z = ecdh(self.secret, &peer)?;
        let r = derive(&z, &self.client_init_msg, server_init_msg, &self.iv_spec)?;
        Ok((self.client_finished_msg, r))
    }
}

/// The SCP session cipher: AES-256-GCM, fixed IV, 128-bit tag (`tf/e.java e`).
#[derive(Clone)]
pub struct SessionCipher {
    key: [u8; 32],
    iv: [u8; 12],
}

impl SessionCipher {
    pub fn new(r: &Ukey2Result) -> Self {
        Self { key: r.session_key, iv: r.session_iv }
    }
    pub fn encrypt(&self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
        Aes256Gcm::new(&self.key.into())
            .encrypt(Nonce::from_slice(&self.iv), plain)
            .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))
    }
    pub fn decrypt(&self, ct: &[u8]) -> anyhow::Result<Vec<u8>> {
        Aes256Gcm::new(&self.key.into())
            .decrypt(Nonce::from_slice(&self.iv), ct)
            .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed (wrong key/iv?)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiator_and_responder_agree() {
        let (init, client_init) = Initiator::new();
        let (resp, server_init) = Responder::new(&client_init).unwrap();
        let (client_finished, ri) = init.finish(&server_init).unwrap();
        let rr = resp.finish(&client_finished).unwrap();
        assert_eq!(ri.auth_string, rr.auth_string);
        assert_eq!(ri.session_key, rr.session_key);
        assert_eq!(ri.session_iv, rr.session_iv);
        let c = SessionCipher::new(&rr);
        assert_eq!(c.decrypt(&SessionCipher::new(&ri).encrypt(b"hi phone").unwrap()).unwrap(), b"hi phone");
    }

    #[test]
    fn rejects_bad_commitment() {
        let (_i, client_init) = Initiator::new();
        let (resp, _) = Responder::new(&client_init).unwrap();
        let (other, _) = Initiator::new();
        let fake = other.client_finished_msg.clone();
        assert!(resp.finish(&fake).is_err());
    }

    #[test]
    fn rejects_point_off_the_curve() {
        let bad = GenericPublicKey { r#type: 1, ec_p256_public_key: Some(EcP256PublicKey { x: vec![1], y: vec![2] }) };
        assert!(decode_public_key(&bad.encode_to_vec()).is_err());
    }

    #[test]
    fn java_bigint_roundtrip() {
        let mut x = [0u8; 32];
        x[0] = 0x80;
        assert_eq!(to_java_bigint(&x).len(), 33);
        assert_eq!(from_java_bigint(&to_java_bigint(&x)).unwrap(), x);
        let mut small = [0u8; 32];
        small[31] = 5;
        assert_eq!(from_java_bigint(&to_java_bigint(&small)).unwrap(), small);
    }

    #[test]
    fn d2d_salt_matches_phone_constant() {
        // h2.b.f19274a in the phone app.
        assert_eq!(
            hex::encode(Sha256::digest(b"D2D")),
            "82aa55a0d397f88346ca1cee8d3909b95f13fa7deb1d4ab38376b8256da85510"
        );
    }
}
