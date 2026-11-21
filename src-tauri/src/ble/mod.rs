//! BLE peripheral — Layer 1 transport for pairing.
//!
//! On Linux this is BlueZ, driven by the `bluer` crate (add to Cargo.toml when
//! implementing; kept out of the dependency set until then so the scaffold
//! builds without a Bluetooth stack).
//!
//! Role: advertise the ONet pairing **GATT service `0xAA16`** (with a companion
//! `0xAA17`), confirmed from `pantaChannelService.exe`:
//!
//! ```text
//!   0000aa16-0000-1000-8000-00805f9b34fb   (16-bit SIG short UUID 0xAA16)
//!   0000aa17-0000-1000-8000-00805f9b34fb   (0xAA17)
//! ```
//!
//! The phone scans for this service (the Windows app advertises it via WinRT
//! `StartAdvertisementInternal` alongside Wi-Fi Direct), connects, and exchanges
//! UKey2 `Ukey2Message` frames over the service's characteristics. We expose that
//! characteristic read/write pair as a [`MessageTransport`] so
//! `pairing::ukey2` can run the handshake over it unchanged.
//!
//! OPEN CAPTURE: the exact characteristic layout (which UUID is write-to-peer vs
//! notify-from-peer, and the fragmentation scheme across BLE MTU) is the one wire
//! detail still worth a `btmon`/Wireshark trace during a real pair. Everything
//! else here is settled.

pub mod probe;

use crate::transport::MessageTransport;

/// The ONet pairing service UUID (16-bit `0xAA16`, expanded to the SIG base).
pub const PAIRING_SERVICE_UUID: &str = "0000aa16-0000-1000-8000-00805f9b34fb";
/// The companion characteristic/service UUID `0xAA17`.
pub const PAIRING_AUX_UUID: &str = "0000aa17-0000-1000-8000-00805f9b34fb";

/// Advertisement payload fields the phone expects (mirrors the WinRT advertiser).
#[derive(Debug, Clone)]
pub struct Advertisement {
    /// Device name shown on the phone.
    pub name: String,
    /// Device type byte (6 = PC — we present as a PC peer).
    pub device_type: u8,
    /// Short device id advertised in the manufacturer/scan-response data.
    pub device_id: String,
}

impl Default for Advertisement {
    fn default() -> Self {
        Self {
            name: "Linux".into(),
            device_type: 6, // PC
            device_id: String::new(),
        }
    }
}

/// A BLE peripheral that advertises the pairing service and yields a transport
/// for the connected central (the phone).
///
/// SCAFFOLD: signatures and UUIDs are final; the bodies are `todo!()` until the
/// `bluer` backend is written. Sketch of the real implementation:
///
/// ```ignore
/// let session = bluer::Session::new().await?;
/// let adapter = session.default_adapter().await?;
/// adapter.set_powered(true).await?;
/// // 1. Register the GATT application: service 0xAA16 with a write char and a
/// //    notify char (layout TBD from the capture).
/// // 2. Register an advertisement carrying `Advertisement` + the service UUID.
/// // 3. On central-connect, wrap the characteristics in `BleTransport`.
/// ```
pub struct BlePeripheral {
    pub advert: Advertisement,
}

impl BlePeripheral {
    pub fn new(advert: Advertisement) -> Self {
        Self { advert }
    }

    /// Begin advertising `0xAA16` and wait for a central to connect; returns a
    /// transport bound to that connection, ready for the UKey2 handshake.
    pub async fn advertise_and_accept(&self) -> anyhow::Result<BleTransport> {
        tracing::warn!(
            service = PAIRING_SERVICE_UUID,
            "ble: advertise_and_accept is a scaffold — wire up the bluer backend"
        );
        todo!("BlueZ GATT peripheral: advertise 0xAA16/0xAA17 and accept a central")
    }
}

/// `MessageTransport` over the connected GATT characteristics. Reassembles the
/// BLE-MTU fragments into whole `Ukey2Message` frames.
pub struct BleTransport {
    // bluer characteristic handles go here (write char + notify stream).
}

impl MessageTransport for BleTransport {
    async fn send(&self, _frame: &[u8]) -> anyhow::Result<()> {
        todo!("fragment `frame` across the write characteristic (respect ATT MTU)")
    }

    async fn recv(&self) -> anyhow::Result<Vec<u8>> {
        todo!("reassemble notifications from the peer into one frame")
    }
}
