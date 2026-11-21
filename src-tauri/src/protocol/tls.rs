//! TLS for the O+ Connect control + file channels.
//!
//! What the SDK does (`WebSocketServer.startServerAsync`,
//! `WebSocketClient.startServerAsync`, `TlsPeerValidator`):
//!
//! * Loads a **bundled** certificate `dotnetty.com.pfx` (password `password`).
//! * If the cert fails to load, it **falls back to an insecure, no-TLS socket**
//!   and logs "Connection will be insecure."
//! * Trust is NOT normal CA validation. `TlsPeerValidator` runs:
//!   - `CheckThumbprintPin`  — certificate thumbprint pinning
//!   - `CheckDevicePairingTrust` — trust tied to the pairing handshake
//!   - plus chain / expiry / policy checks as secondary signals.
//!
//! We generate a fresh self-signed identity per run for our own TLS server
//! (`scp::pcsend`); the phone's OPPO Share client doesn't verify it.

use rcgen::{CertificateParams, DistinguishedName, DnType};

/// A generated self-signed identity: PEM cert + PEM private key.
pub struct SelfSignedIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a self-signed certificate for the control/file server.
///
/// This stands in for the app's bundled `dotnetty.com.pfx`. Whether the phone
/// accepts an arbitrary self-signed cert, or pins a specific thumbprint, is the
/// open question flagged in the plan — confirm with a capture.
pub fn generate_identity(common_name: &str) -> anyhow::Result<SelfSignedIdentity> {
    let mut params = CertificateParams::new(vec![common_name.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok(SelfSignedIdentity {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}
