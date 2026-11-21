//! The O+ Connect file-transfer message layer (from the .NET `OShareTransferSDK`).
//!
//! * [`messages`] — control-message types, status codes, versions, wire codec
//! * [`tls`]      — self-signed identity for our TLS server

pub mod messages;
pub mod tls;
