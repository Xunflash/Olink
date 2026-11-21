//! Peer discovery — findability over Wi-Fi/BLE.
//!
//! This is distinct from [`crate::ble`] (which carries the *pairing* handshake):
//! discovery is how the phone and the Linux host find each other's addresses. On
//! the Windows app it lives in `pantaConnSDKDll.dll` (OPPO's "Panta / ONet" SDK,
//! a libuv UDP event bus). What we now know:
//!
//! | Concern        | Windows behaviour                                  | Linux replacement           |
//! |----------------|----------------------------------------------------|-----------------------------|
//! | BLE advertise  | WinRT `StartAdvertisementInternal`, service `0xAA16`/`0xAA17` | BlueZ (`bluer`), see `ble` |
//! | ONet discovery | UDP event bus, listener on **port 46888**          | `tokio` UDP + the ONet frames |
//! | Wi-Fi Direct   | `connType 8` advertise                             | `wpa_supplicant` / `wpa_cli` |
//! | mDNS (fallback)| —                                                  | `mdns-sd` crate             |
//! | Peer address   | QR `oconn.addr` = `ip:46888`                       | `Peer.ip` below             |
//!
//! Addressing is well understood (QR `oconn` carries `ip:46888`; ONet announces
//! over UDP). The remaining detail is the exact ONet announce-frame bytes, which
//! a short LAN capture pins down; BLE discovery uses the known `0xAA16` service.

pub mod qr_probe;

use serde::Serialize;

/// A discovered peer device.
#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    /// Stable device id (ONet `getDeviceId` equivalent).
    pub device_id: String,
    /// Human-readable name shown in the UI.
    pub name: String,
    /// Transport the peer was found on.
    pub transport: Transport,
    /// IP address, once a Wi-Fi/P2P link is up (None while BLE-only).
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Transport {
    Ble,
    WifiDirect,
    Lan,
}

/// A discovery backend. Implemented per transport; the app can run several.
#[allow(async_fn_in_trait)]
pub trait Discovery {
    /// Begin scanning. Emits peers through `on_peer` as they appear.
    async fn start(&self, on_peer: Box<dyn Fn(Peer) + Send + Sync>) -> anyhow::Result<()>;
    /// Stop scanning.
    async fn stop(&self) -> anyhow::Result<()>;
}

/// A placeholder backend that returns a single fake peer so the UI and the
/// transfer code can be exercised without hardware. Replace with real BlueZ /
/// Wi-Fi backends.
pub struct MockDiscovery;

impl Discovery for MockDiscovery {
    async fn start(&self, on_peer: Box<dyn Fn(Peer) + Send + Sync>) -> anyhow::Result<()> {
        tracing::warn!("MockDiscovery: emitting a fake peer — no real scan is running");
        on_peer(Peer {
            device_id: "mock-device-0001".into(),
            name: "Mock OnePlus".into(),
            transport: Transport::Lan,
            ip: Some("127.0.0.1".into()),
        });
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TODO(discovery): real backends.
//
// pub struct BleDiscovery { /* bluer session */ }
// impl Discovery for BleDiscovery { ... }   // scan for the ONet service UUID
//
// pub struct LanDiscovery { /* mdns-sd daemon */ }
// impl Discovery for LanDiscovery { ... }   // browse the mDNS service type
//
// Wi-Fi Direct is driven out-of-process via wpa_supplicant control socket;
// wrap `wpa_cli p2p_find` / `p2p_connect` or talk the control protocol directly.
// ---------------------------------------------------------------------------
