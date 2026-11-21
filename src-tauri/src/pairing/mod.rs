//! Discovery & pairing — mapped from the ONet logs. See PAIRING.md for the full
//! write-up. Headline result after the cross-account capture:
//!
//! * **Discovery / addressing is easy.** The phone finds the PC over ONet (a
//!   UDP event bus), or via a QR code that is just a URL carrying the PC's
//!   address — see [`OConn`]. No BLE needed on a shared LAN.
//! * **There are TWO trust paths, and they are different:**
//!     1. **Same account** (`is_same_account:true`): the OPPO account-match
//!        handshake (module 21, `op 0/200/204`) — both peers prove they hold the
//!        signed-in account's key list. Silent, no user prompt. See
//!        [`account_match`]. Needs account key material — hard for a clean room.
//!     2. **Cross account** (`is_same_account:false`): a per-device
//!        **challenge-response + user-confirm** handshake (the `authentication`
//!        module), `pairType: 0`. **`account_match` never runs** on this path —
//!        CAPTURE-VERIFIED (count = 0). This is a UKey2-style numeric-comparison
//!        pairing and needs **no OPPO account**. See [`confirm_pair`].
//!
//! Path 2 is the one a Linux client can actually implement, and static analysis
//! of the binaries settled exactly what it is: **standard Google UKey2 (cipher
//! `P256_SHA512`) + SecureMessage**, vendored verbatim from `google/ukey2`. So
//! there is NO proprietary crypto to reimplement — link the published library.
//! Full spec in `CRYPTO.md`. Key facts: ECDH P-256 (NID `0x19f`, confirmed in
//! disassembly), HKDF-SHA256 with the stock salts `UKEY2 v1 auth` / `UKEY2 v1
//! next`, SecureMessage D2D over AES-256-CBC + HMAC-SHA256, and the 8-byte `RC`
//! is the UKey2 verification string truncated to 8 bytes. BLE transport is GATT
//! service `0xAA16`/`0xAA17`.

use serde::{Deserialize, Serialize};

/// The UKey2 handshake driver (Layer 1). Runs the actual key exchange over a
/// `MessageTransport`; see [`ukey2::run_server`].
pub mod ukey2;

/// The `oconn` object a PC encodes into its pairing QR. The QR itself is the
/// URL `https://pc-assistant-eu.allawnofs.com/h5/index.html?param={"oconn":{..}}`.
/// CAPTURE-VERIFIED from `render.log`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OConn {
    /// Bluetooth MAC of the advertiser.
    pub bm: String,
    /// Wi-Fi-Direct (P2P) MAC.
    #[serde(default)]
    pub pm: String,
    /// Device id.
    pub dvd: String,
    pub name: String,
    pub model: String,
    /// ONet listener address, `ip:port` (e.g. the PC on `:46888`). The peer
    /// connects here after scanning.
    pub addr: String,
    /// Device type: 6 = PC.
    pub d_type: i32,
    pub ver: i32,
    /// OPPO account hash. Present even cross-account, but on the cross-account
    /// path it is NOT used as the trust root — the confirm code is. Both peers
    /// sharing one value is what selects the silent same-account path instead.
    pub acc: String,
    #[serde(default)]
    pub cp: String,
    #[serde(default)]
    pub lang: String,
}

impl OConn {
    /// Build the QR URL this `oconn` would be encoded as.
    pub fn to_qr_url(&self) -> Result<String, serde_json::Error> {
        let param = serde_json::to_string(&serde_json::json!({ "oconn": self }))?;
        Ok(format!(
            "https://pc-assistant-eu.allawnofs.com/h5/index.html?param={param}"
        ))
    }
}

/// **Cross-account pairing (the implementable path).** Reconstructed from the
/// native `fastPair` + `authentication` modules in `pantaServiceDlog`, over two
/// captured sessions (one warm reconnect, one cold re-pair with the on-screen
/// "Allow this device?" dialog). No account key is involved.
///
/// It is **two layers**, and the human confirm + key agreement are in layer 1:
///
/// ```text
///   LAYER 1 — Bluetooth fast-pair (module `fastPair`)
///     • BLE connect + "Allow this device to connect?" dialog = HUMAN CONFIRM.
///     • UKey2/ECDH key agreement  → derives KSC (shared session key).
///     • EVT_SAVE_KSC_INFO_REQ → keyMgrSaveKsc "save ksc to memory success"
///     • keyMgrSavePeerDeviceId <id> → PeerDeviceId table  (persistent trust;
///       this is why every later reconnect is silent — no prompt).
///   ────────────────── KSC now held by both sides ──────────────────
///   LAYER 2 — WiFi/ONet re-proof (module `authentication`)
///     EVT_ACCESSORY_CREATE_IND → EVT_ACCESSORY_IDENTITY_SUCCESS
///     getKsc "Get KSC success"                  (loads key from layer 1)
///     generateServerChallengeMac / generateClientChallengeMac
///     checkRemoteParams: RC == generateRC  →  "check succeed!"
///     AUTH_SERVER_WAIT_FOR_CONFIRM → checkRc2 → "auth success"  (~7 ms,
///        does NOT wait for a human — the confirm already happened in layer 1)
///   ───────────▶  AES-GCM D2D session (transfer protocol in PROTOCOL.md)
/// ```
///
/// Key facts, all CAPTURE-VERIFIED:
/// * The flow is **accessory authentication** (`EVT_ACCESSORY_*`,
///   `authParseAccessoryRequest`) — same family as Google Fast Pair / MFi.
/// * `RC` is an **8-byte** value both peers derive from KSC and compare; equality
///   is the WiFi-side re-proof. Captured equal on both sessions:
///   `f6 7b ce 14 40 96 8e 06` (warm) and `53 28 0a 12 cf 05 27 48` (cold).
/// * `KSC` is agreed over BLE in layer 1 and **persisted** (key manager +
///   `PeerDeviceId` table), so first pair prompts and reconnects are silent.
/// * `account_match` (module 21) is **not the gate**: on a signed-out PC it
///   appears only *after* `auth success`, `i32Encrypt: 0`, no `keyId`.
/// * The curve + HKDF labels that derive KSC are **not in the logs** — they are
///   in `pantaConnSDKDll` (`cryptoUkey2DoKeyAgreement` / `cryptoUkey2Hkdf`).
///   Working assumption: ECDH P-256 + HKDF-SHA256 → AES-256-GCM.
pub mod confirm_pair {
    /// Phases of the pairing, spanning both layers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Phase {
        /// Layer 1: BLE connected, "Allow this device?" shown to the user.
        BleAwaitingConfirm,
        /// Layer 1: user accepted; UKey2/ECDH done; KSC derived and saved.
        KscEstablished,
        /// Layer 2: WiFi accessory auth; `RC == generateRC` re-proof matched.
        ShortCodeMatched,
        /// Layer 2: `checkRc2` ok, `auth success`; AES-GCM session open.
        Confirmed,
    }

    /// The 8-byte challenge value both peers derive from KSC and compare on the
    /// WiFi side. Observed: `f6 7b ce 14 40 96 8e 06`, `53 28 0a 12 cf 05 27 48`.
    pub const RC_LEN: usize = 8;

    /// The symmetric session key agreed over BLE (`getKsc`) and persisted.
    /// Established by UKey2 (cipher `P256_SHA512`): ECDH P-256 → HKDF-SHA256
    /// (salts `UKEY2 v1 auth` / `UKEY2 v1 next`) → a SecureMessage D2D context
    /// (AES-256-CBC + HMAC-SHA256). See CRYPTO.md. Prefer linking `google/ukey2`
    /// over reimplementing this.
    #[derive(Debug, Clone)]
    pub struct Ksc(pub Vec<u8>);
}

/// **Same-account fast path (optional).** The account-match handshake messages
/// (ONet D2D, module 21, `account_match_msg_type`). Body is hex-encoded JSON
/// with an `op` sequence: `0` (version init) -> `200` (salted keyed challenge)
/// -> `204` (encrypted token). CAPTURE-VERIFIED shapes — see PAIRING.md. Only
/// runs when both devices are signed into the SAME OPPO account; a Linux client
/// does not need this path and can ignore it.
pub mod account_match {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Op0Init {
        pub ver: Vec<i32>, // e.g. [256, 512]
        pub op: i32,       // 0
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Op200Challenge {
        #[serde(rename = "type")]
        pub kind: i32,
        pub salt: String, // base64, 24 bytes
        pub id: String,   // base64, 32 bytes
        /// Identifies which account key: `"1_<64 hex>"`.
        #[serde(rename = "keyId")]
        pub key_id: String,
        #[serde(rename = "keyListVer")]
        pub key_list_ver: i32,
        pub region: String, // e.g. "GB"
        pub ts: i64,
        pub op: i32, // 200
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Op204Token {
        /// Encrypted token string.
        pub ets: String,
        pub op: i32, // 204
    }

    /// The account-identity companion message (module 16003).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AccountIdentity {
        pub randomid: String,
        pub switch: i32,
        pub device_id: String,
        pub account_hash: String,
        pub is_log_triggered: bool,
    }
}

/// The result of a completed pairing: an authenticated session plus the
/// control/file address the WebSocket layer then uses.
#[derive(Debug, Clone, Serialize)]
pub struct PairedSession {
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("pairing not implemented yet: cross-account confirm handshake (see confirm_pair / PAIRING.md)")]
    NotImplemented,
    #[error("peer wants the same-account path; re-run from a signed-out PC to force the confirm path")]
    SameAccountPathOnly,
    #[error("handshake failed: {0}")]
    Handshake(String),
}

/// Pair with a peer. The real flow now lives in the composed architecture:
/// [`crate::app::ConnectionManager`] advertises BLE, hands the GATT link to
/// [`ukey2::run_server`] as a `MessageTransport`, gates on the Allow dialog, and
/// persists the resulting [`ukey2::D2DContext`] via [`crate::trust`]. The crypto
/// is standard UKey2 (`P256_SHA512`) — link `google/ukey2`, don't reimplement.
///
/// This free function is kept only as the convenience entry the Tauri command
/// calls; it delegates to the orchestrator once that path is wired.
pub async fn pair(device_id: &str) -> Result<PairedSession, PairingError> {
    tracing::warn!(device_id, "pairing: drive via app::ConnectionManager (UKey2 over BLE)");
    let _ = device_id;
    Err(PairingError::NotImplemented)
}
