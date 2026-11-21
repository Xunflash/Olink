//! UKey2 pairing driver (Layer 1).
//!
//! Runs the **Google UKey2** authenticated key exchange — cipher `P256_SHA512` —
//! over a [`MessageTransport`] (the BLE GATT link), producing a [`D2DContext`]
//! of derived keys that `trust` then persists. This is the exact handshake the
//! Windows `pantaChannelService.exe` runs; see CRYPTO.md for the evidence.
//!
//! **Do not reimplement the crypto.** Link the published `google/ukey2` (C++ via
//! a thin FFI wrapper, or a Rust port). This module is the *driver*: it owns the
//! message ordering, the transport, and the confirm step — the library owns the
//! ECDH / HKDF / SecureMessage math. The seam makes both halves testable.
//!
//! Handshake (server role = us, the peer the phone connects to):
//! ```text
//!   recv ClientInit      (cipher_commitments incl. P256_SHA512, SHA-512 commit)
//!   send ServerInit      (our EcP256PublicKey)
//!   recv ClientFinished  (their EcP256PublicKey)   → ECDH P-256 → secret Z
//!   derive via HKDF-SHA256, salts "UKEY2 v1 auth" / "UKEY2 v1 next":
//!       verification string  → the 8-byte RC (shown/confirmed)
//!       next-protocol secret → D2D keys (SecureMessage AES-256-CBC + HMAC-SHA256)
//!   await user "Allow"   → commit the D2DContext
//! ```

use crate::transport::MessageTransport;
use crate::trust::TrustRecord;

/// The keys and identity that fall out of a completed UKey2 handshake. This is
/// the thing worth persisting; [`to_trust_record`](D2DContext::to_trust_record)
/// turns it into the stored form.
#[derive(Debug, Clone)]
pub struct D2DContext {
    /// Peer device id learned during the handshake.
    pub peer_id: String,
    pub peer_name: String,
    /// The derived SecureMessage D2D key material (the KSC).
    pub ksc: Vec<u8>,
}

impl D2DContext {
    pub fn to_trust_record(&self) -> TrustRecord {
        TrustRecord {
            peer_id: self.peer_id.clone(),
            name: self.peer_name.clone(),
            ksc: self.ksc.clone(),
            paired_at: now_unix(),
        }
    }
}

/// How the user authorises a pairing. The handshake blocks on this between the
/// key agreement and committing the context — it is the "Allow this device?"
/// decision (Layer 1), the real trust gate.
#[allow(async_fn_in_trait)]
pub trait ConfirmPrompt: Send + Sync {
    /// Show the peer (and, if the UX wants it, the UKey2 verification string /
    /// 8-byte RC) and resolve `true` iff the user allows the connection.
    async fn confirm(&self, peer_name: &str, verification: &[u8]) -> bool;
}

/// Auto-allow — for headless/testing only. A shipping build uses a real dialog.
pub struct AllowAll;
impl ConfirmPrompt for AllowAll {
    async fn confirm(&self, _peer: &str, _verification: &[u8]) -> bool {
        true
    }
}

/// Drives one UKey2 handshake to completion over `transport`.
///
/// SCAFFOLD: the ordering, the confirm seam and the output type are final; the
/// `todo!()` bodies are where the `google/ukey2` calls go. Reference sketch:
///
/// ```ignore
/// let mut hs = ukey2::ServerHandshake::new(Cipher::P256_SHA512);
/// let client_init = transport.recv().await?;
/// let server_init = hs.handle_client_init(&client_init)?;
/// transport.send(&server_init).await?;
/// let client_finished = transport.recv().await?;
/// hs.handle_client_finished(&client_finished)?;
/// let verification = hs.auth_string(RC_LEN);              // "UKEY2 v1 auth"
/// if !confirm.confirm(peer_name, &verification).await { bail!("declined"); }
/// let conn = hs.into_connection_context();                // "UKEY2 v1 next"
/// Ok(D2DContext { peer_id, peer_name, ksc: conn.encode_key() })
/// ```
pub async fn run_server<T: MessageTransport, C: ConfirmPrompt>(
    transport: &T,
    confirm: &C,
) -> anyhow::Result<D2DContext> {
    let _ = (transport, confirm);
    tracing::warn!("ukey2: run_server is a scaffold — link google/ukey2 (P256_SHA512)");
    todo!("drive the UKey2 server handshake over `transport`, gated by `confirm`")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
