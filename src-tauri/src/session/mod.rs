//! Authenticated session (Layer 2).
//!
//! Once a peer is in the [`crate::trust`] store, reconnects skip UKey2 entirely.
//! The phone comes in over Wi-Fi and the two sides run the lightweight
//! `authentication` re-proof (the native module of the same name): load the
//! stored KSC (`getKsc`), exchange the challenge MACs, compare the 8-byte `RC`
//! (`checkRemoteParams` / `checkRc2`), and the channel is live. From there the
//! bulk traffic is **AES-128-GCM** (`cryptoAesGcm*`) and carries the transfer
//! protocol in [`crate::protocol`].
//!
//! This module is the bridge: a [`TrustRecord`] in, a ready control/file channel
//! out. It owns the Layer-2 crypto context so `protocol` stays transport-plain.

use crate::trust::TrustRecord;

/// A live, authenticated link to a peer, ready for the transfer protocol.
pub struct Session {
    pub peer_id: String,
    /// Peer control/file endpoint (`ip:port`, ONet listener — `:46888` region).
    pub endpoint: String,
    // AES-128-GCM context derived from the trust record goes here.
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no trust record for peer — pair first")]
    NotPaired,
    #[error("re-proof failed (RC mismatch or stale key): {0}")]
    ReProof(String),
    #[error("transport error: {0}")]
    Transport(String),
}

impl Session {
    /// Resume a silent session with a known peer using its stored key. Runs the
    /// Wi-Fi `authentication` re-proof, then returns a ready [`Session`].
    ///
    /// SCAFFOLD: the signature and flow are final; the body wires the re-proof
    /// and the AES-128-GCM context. Reference sketch:
    ///
    /// ```ignore
    /// let ksc = record.ksc;                 // from getKsc-equivalent storage
    /// let chan = connect_onet(&endpoint).await?;
    /// let rc_local  = server_challenge_mac(&ksc, &transcript);   // 8 bytes
    /// let rc_remote = chan.exchange_challenge(&rc_local).await?;
    /// if rc_local != rc_remote { return Err(SessionError::ReProof("RC mismatch".into())); }
    /// let gcm = AesGcm128::new(session_key_from(&ksc));
    /// Ok(Session { peer_id: record.peer_id, endpoint, /* gcm */ })
    /// ```
    pub async fn resume(record: &TrustRecord, endpoint: String) -> Result<Session, SessionError> {
        tracing::warn!(peer = %record.peer_id, endpoint, "session: resume is a scaffold");
        let _ = (record, &endpoint);
        todo!("Wi-Fi authentication re-proof (RC from stored KSC) + AES-128-GCM context")
    }

    /// Seal an outbound protocol frame with the session's AES-128-GCM context.
    pub fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        todo!("AES-128-GCM encrypt (cryptoAesGcmNoPaddingEn equivalent)")
    }

    /// Open an inbound protocol frame.
    pub fn open(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        todo!("AES-128-GCM decrypt (cryptoAesGcmNoPaddingDe equivalent)")
    }
}
