//! SCP — O+ Connect's secure channel protocol over TCP (see `SCP.md`).
//!
//! After a QR scan the phone (SCP client) connects to the PC on TCP **10152**.
//! This module provides the wire framing and message types; [`ukey2`] the
//! OPPO-flavoured UKey2 responder; [`server`] the server state machine.

pub mod dbr;
pub mod epi;
pub mod icdf;
pub mod oshare;
pub mod castrx;
pub mod uibc;
pub mod odmf;
pub mod pcsend;
pub mod phoneapps;
pub mod pcclip;
pub mod server;
pub mod ukey2;

use prost::Message;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SCP_PORT: u16 = 10152;
pub const SCP_VERSION: u8 = 4;
pub const PAYLOAD_PROTOBUF: u8 = 3;

/// `ScpMessageType`.
pub mod msg_type {
    pub const HELLO: i32 = 0;
    pub const SYNC: i32 = 1;
    pub const SYNC_SECURE: i32 = 2;
    pub const UKEY2_INIT: i32 = 3;
    pub const UKEY2_FINISHED: i32 = 4;
    pub const DISCONNECT: i32 = 65535;

    pub fn name(t: i32) -> &'static str {
        match t {
            HELLO => "HELLO",
            SYNC => "SYNC",
            SYNC_SECURE => "SYNC_SECURE",
            UKEY2_INIT => "UKEY2_INIT",
            UKEY2_FINISHED => "UKEY2_FINISHED",
            5 => "OOBKEY_BUILD",
            6 => "OOBKEY_PROCESS",
            7 => "OOBKEY_FINISHED",
            DISCONNECT => "DISCONNECT",
            _ => "?",
        }
    }
}

/// The 12-byte SCP main header (`MainHeader`, serializer `mm/c.java h0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub service_type: u8,
    pub payload_type: u8,
    pub encrypted: bool,
    pub is_server: bool,
    pub struct_type: u8,
    pub payload_len: u16,
    pub next_header: u8,
    pub is_hello: bool,
    pub crc_enabled: bool,
    pub crc: u16,
    pub agent_address: [u8; 4],
}

impl Header {
    pub const LEN: usize = 12;

    pub fn encode(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0] = (self.version << 4) | (self.service_type & 0x0f);
        b[1] = (self.payload_type << 4)
            | ((self.encrypted as u8) << 3)
            | ((self.is_server as u8) << 2)
            | (self.struct_type & 0x03);
        b[2..4].copy_from_slice(&self.payload_len.to_be_bytes());
        b[4] = self.next_header;
        b[5] = ((self.is_hello as u8) << 1) | (self.crc_enabled as u8);
        b[6..8].copy_from_slice(&self.crc.to_be_bytes());
        b[8..12].copy_from_slice(&self.agent_address);
        b
    }

    pub fn decode(b: &[u8; 12]) -> Self {
        Self {
            version: b[0] >> 4,
            service_type: b[0] & 0x0f,
            payload_type: b[1] >> 4,
            encrypted: b[1] & 0x08 != 0,
            is_server: b[1] & 0x04 != 0,
            struct_type: b[1] & 0x03,
            payload_len: u16::from_be_bytes([b[2], b[3]]),
            next_header: b[4],
            is_hello: b[5] & 0x02 != 0,
            crc_enabled: b[5] & 0x01 != 0,
            crc: u16::from_be_bytes([b[6], b[7]]),
            agent_address: [b[8], b[9], b[10], b[11]],
        }
    }
}

/// `AgentAddress`: last 4 bytes of SHA-256(namespace + channel).
pub fn agent_address(channel: &str, namespace: &str) -> [u8; 4] {
    let d = Sha256::digest(format!("{namespace}{channel}").as_bytes());
    [d[28], d[29], d[30], d[31]]
}

// ---- protobuf messages (field numbers from the phone's generated classes) ----

#[derive(Clone, PartialEq, Message)]
pub struct ScpPacket {
    #[prost(int32, tag = "1")]
    pub msg_type: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Hello {
    #[prost(int32, tag = "1")]
    pub sequence_no: i32,
    #[prost(string, tag = "2")]
    pub channel: String,
    #[prost(string, tag = "3")]
    pub namespace: String,
    #[prost(string, tag = "4")]
    pub service_name: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Sync {
    #[prost(string, tag = "1")]
    pub device_name: String,
    #[prost(int32, tag = "2")]
    pub key_type: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub custom_data: Vec<u8>,
    #[prost(int32, tag = "4")]
    pub device_type: i32,
    #[prost(int32, tag = "5")]
    pub active_trigger_mode: i32,
    #[prost(string, tag = "6")]
    pub model_id: String,
    #[prost(int32, tag = "7")]
    pub link_type: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct SyncSecure {
    #[prost(string, tag = "1")]
    pub device_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub ksc: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ksc_alias: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Disconnect {
    #[prost(int32, tag = "1")]
    pub sequence_no: i32,
    #[prost(int32, tag = "2")]
    pub disconnect_code: i32,
    #[prost(string, tag = "3")]
    pub disconnect_reason: String,
}

/// One received SCP frame: header + raw (possibly encrypted) payload.
#[derive(Debug, Clone)]
pub struct Frame {
    pub header: Header,
    pub extra_headers: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Read one frame. Fragment headers (`next_header` = 1) are captured raw;
/// they haven't been observed on the pairing path yet.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Frame> {
    let mut hb = [0u8; Header::LEN];
    r.read_exact(&mut hb).await?;
    let header = Header::decode(&hb);
    let mut extra_headers = Vec::new();
    let mut next = header.next_header;
    while next != 0 {
        // Peer-controlled chain: bound it (a real frame has one or two).
        anyhow::ensure!(extra_headers.len() < 1024, "too many SCP fragment headers");
        // FragmentHeader: [next][len][..len-2 more bytes]
        let mut two = [0u8; 2];
        r.read_exact(&mut two).await?;
        let len = two[1] as usize;
        let mut rest = vec![0u8; len.saturating_sub(2)];
        r.read_exact(&mut rest).await?;
        extra_headers.extend_from_slice(&two);
        extra_headers.extend_from_slice(&rest);
        next = two[0];
    }
    let mut payload = vec![0u8; header.payload_len as usize];
    r.read_exact(&mut payload).await?;
    Ok(Frame { header, extra_headers, payload })
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    mut header: Header,
    payload: &[u8],
) -> anyhow::Result<()> {
    header.payload_len = u16::try_from(payload.len())?;
    let mut buf = header.encode().to_vec();
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact HELLO the phone sent us on 2026-11-19.
    const PHONE_HELLO: &str = "40300036000200007b08ad12123408cefacbe1feffffffff0112116163746976655f636f6e6e656374696f6e1a14636f6d2e6865797461702e6163636573736f7279";

    #[test]
    fn decodes_captured_phone_hello() {
        let bytes = hex::decode(PHONE_HELLO).unwrap();
        let h = Header::decode(bytes[..12].try_into().unwrap());
        assert_eq!(h.version, 4);
        assert_eq!(h.payload_type, PAYLOAD_PROTOBUF);
        assert!(h.is_hello && !h.is_server && !h.encrypted);
        assert_eq!(h.payload_len as usize, bytes.len() - 12);
        assert_eq!(h.encode().as_slice(), &bytes[..12], "header must re-encode identically");

        let pkt = ScpPacket::decode(&bytes[12..]).unwrap();
        assert_eq!(pkt.msg_type, msg_type::HELLO);
        let hello = Hello::decode(pkt.data.as_slice()).unwrap();
        assert_eq!(hello.sequence_no, -332202674);
        assert_eq!(hello.channel, "active_connection");
        assert_eq!(hello.namespace, "com.heytap.accessory");
        assert_eq!(h.agent_address, agent_address(&hello.channel, &hello.namespace));
        // Re-encoding the payload reproduces the phone's bytes exactly.
        assert_eq!(pkt.encode_to_vec(), &bytes[12..]);
    }

    #[test]
    fn decodes_captured_phone_disconnect() {
        let bytes = hex::decode("40300052000000007b08ad1208ffff03124c08cffacbe1feffffffff0110d2131a3c54696d6564206f75742077616974696e6720666f722035303030206d73205b54696d656f757443616e63656c6c6174696f6e457863657074696f6e5d").unwrap();
        let pkt = ScpPacket::decode(&bytes[12..]).unwrap();
        assert_eq!(pkt.msg_type, msg_type::DISCONNECT);
        let d = Disconnect::decode(pkt.data.as_slice()).unwrap();
        assert_eq!(d.disconnect_code, 2514);
        assert!(d.disconnect_reason.starts_with("Timed out"));
    }
}
