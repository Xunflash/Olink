//! The connection lifecycle the UI reflects.
//!
//! One peer moves through these states. First contact runs the full UKey2 path;
//! a known peer jumps straight to `Resuming`. Keeping this as an explicit enum
//! (rather than scattered booleans) is what lets the UI show an honest status and
//! lets the orchestrator reason about what to do next.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum Lifecycle {
    /// Nothing running.
    Idle,
    /// BLE advertising `0xAA16` + discovery backends are up; waiting for a peer.
    Advertising,
    /// A peer connected over BLE; UKey2 handshake in progress (first-time pair).
    Pairing { peer_name: String },
    /// Blocked on the user's "Allow this device?" decision. `rc` is the 8-byte
    /// UKey2 verification string, for display if the UX wants it.
    AwaitingConfirm { peer_name: String, rc: Vec<u8> },
    /// Known peer; running the Wi-Fi re-proof from the stored key (silent).
    Resuming { peer_id: String },
    /// Authenticated session is live; the transfer protocol can run.
    Connected { peer_id: String, endpoint: String },
    /// Something failed; carries a human-readable reason.
    Failed { reason: String },
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle::Idle
    }
}
