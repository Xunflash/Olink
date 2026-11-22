//! How the phone finds this computer and connects to it.
//!
//! There is no network discovery to do: the phone gets our address from the
//! pairing QR (`oconn.addr`) and connects in, and afterwards it reconnects to
//! the PC it remembers. [`qr_probe`] builds that QR and runs the connection.

pub mod qr_probe;
