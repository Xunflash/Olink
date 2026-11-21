//! Bluetooth LE research tools.
//!
//! Olink does not use Bluetooth to pair or to talk to the phone: first contact
//! is Wi-Fi (the phone opens SCP to us on TCP 10152 after scanning the QR, see
//! `SCP.md`). Early on, the Windows app's logs suggested pairing ran over a BLE
//! GATT service, so this module holds the probe used to test that theory; the
//! phone's own code later showed the Wi-Fi path (`PAIRING.md` has the history).
//!
//! It stays as a diagnostic, `olink ble-probe` (see [`probe`]).

pub mod probe;

/// The ONet GATT service the Windows app advertises (16-bit `0xAA16`).
pub const PAIRING_SERVICE_UUID: &str = "0000aa16-0000-1000-8000-00805f9b34fb";
/// Its companion UUID (`0xAA17`).
pub const PAIRING_AUX_UUID: &str = "0000aa17-0000-1000-8000-00805f9b34fb";
