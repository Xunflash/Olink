//! The seam that lets the handshake and the session share code.
//!
//! UKey2 is transport-agnostic: it sends a message and waits for the peer's
//! reply, nothing more. Pairing happens over **BLE GATT** (Layer 1) and the
//! authenticated session happens over a **Wi-Fi socket** (Layer 2), but both are
//! just "framed bytes in, framed bytes out". Expressing that as one trait means:
//!
//!   * `pairing::ukey2` is written against `MessageTransport`, not against BlueZ,
//!     so it can be unit-tested over [`MemoryTransport`] with no radio;
//!   * the same driver works unchanged once the real BLE transport lands;
//!   * the Wi-Fi session reuses the identical abstraction.
//!
//! Frames are whole protocol messages (a `Ukey2Message`, a control frame). The
//! transport owns framing/MTU — BLE splits across characteristic writes, the
//! socket uses length-prefixing — so callers never see partial messages.

use std::collections::VecDeque;
use std::sync::Mutex;

/// A bidirectional, message-framed channel to the peer.
#[allow(async_fn_in_trait)]
pub trait MessageTransport: Send + Sync {
    /// Send one complete frame to the peer.
    async fn send(&self, frame: &[u8]) -> anyhow::Result<()>;

    /// Receive the next complete frame from the peer. Resolves when a whole
    /// frame has arrived (the impl reassembles fragments).
    async fn recv(&self) -> anyhow::Result<Vec<u8>>;

    /// Close the channel. Idempotent.
    async fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// An in-process transport for tests: whatever you `send` can be drained by the
/// paired half's `recv`. Lets the UKey2 driver run end to end with no hardware.
#[derive(Default)]
pub struct MemoryTransport {
    pub outbound: Mutex<VecDeque<Vec<u8>>>,
    pub inbound: Mutex<VecDeque<Vec<u8>>>,
}

impl MemoryTransport {
    /// Feed a frame as if the peer had sent it (test helper).
    pub fn inject_inbound(&self, frame: Vec<u8>) {
        self.inbound.lock().unwrap().push_back(frame);
    }
    /// Take a frame the code under test sent (test helper).
    pub fn take_outbound(&self) -> Option<Vec<u8>> {
        self.outbound.lock().unwrap().pop_front()
    }
}

impl MessageTransport for MemoryTransport {
    async fn send(&self, frame: &[u8]) -> anyhow::Result<()> {
        self.outbound.lock().unwrap().push_back(frame.to_vec());
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<Vec<u8>> {
        self.inbound
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("MemoryTransport: no inbound frame queued"))
    }
}
