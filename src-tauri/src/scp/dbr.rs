//! DataBus router ("DBR") messages, carried on reserved session 8 after KSC
//! auth (`session/reserved/m.java`, `datatrans/dbr/*`, header builder
//! `d/b.java d()`, serializer `wifilink/negotiation/o.J`).
//!
//! Session-8 body = DataBus header (3 bytes) ‖ payload:
//!   byte0 = (dbType << 3 & 0x38) | (encrypted ? 4 : 0) | (flag ? 1 : 0);  u16 BE message id
//! When encrypted, payload = [`super::epi::AppCipher`] output.
//!
//! Decrypted router message (all big-endian, ids are 6 raw bytes):
//! ```text
//! [6] sender  [8] seq  [6] source  [6] destination
//! u8 msgType (3 = hello, 2 = topology, 1 = …)  u8 version (7)  u16 (0x0100)
//! u8 0  u32 255  u32 255  u32 255  u8 1
//! u32 n  n × [6] route list   u32 extraLen  [extraLen] extra
//! JSON payload (rest), e.g. {"mPayLoad":{…},"mPayLoadType":1}
//! ```

pub const DATABUS_SESSION: u16 = 8;
pub const MSG_TOPO: u8 = 2;
pub const MSG_HELLO: u8 = 3;

#[derive(Debug, Clone)]
pub struct RouterMsg {
    pub sender: [u8; 6],
    pub seq: u64,
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub msg_type: u8,
    pub version: u8,
    pub short: u16,
    pub route: Vec<[u8; 6]>,
    pub extra: Vec<u8>,
    pub payload: Vec<u8>,
}

impl RouterMsg {
    pub fn parse(b: &[u8]) -> anyhow::Result<Self> {
        let six = |i: usize| -> anyhow::Result<[u8; 6]> { Ok(b.get(i..i + 6).ok_or_else(|| anyhow::anyhow!("short"))?.try_into()?) };
        anyhow::ensure!(b.len() >= 26 + 4 + 1 + 12 + 1 + 4, "router msg too short ({})", b.len());
        let sender = six(0)?;
        let seq = u64::from_be_bytes(b[6..14].try_into()?);
        let source = six(14)?;
        let destination = six(20)?;
        let msg_type = b[26];
        let version = b[27];
        let short = u16::from_be_bytes([b[28], b[29]]);
        let mut i = 30 + 1 + 12 + 1;
        let n = u32::from_be_bytes(b[i..i + 4].try_into()?) as usize;
        i += 4;
        let mut route = Vec::with_capacity(n.min(64)); // n is peer-supplied
        for _ in 0..n {
            route.push(six(i)?);
            i += 6;
        }
        let xl = u32::from_be_bytes(b.get(i..i + 4).ok_or_else(|| anyhow::anyhow!("short"))?.try_into()?) as usize;
        i += 4;
        let extra = b.get(i..i + xl).ok_or_else(|| anyhow::anyhow!("short"))?.to_vec();
        i += xl;
        Ok(Self { sender, seq, source, destination, msg_type, version, short, route, extra, payload: b[i..].to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.sender);
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.source);
        b.extend_from_slice(&self.destination);
        b.push(self.msg_type);
        b.push(self.version);
        b.extend_from_slice(&self.short.to_be_bytes());
        b.push(0);
        for _ in 0..3 {
            b.extend_from_slice(&255u32.to_be_bytes());
        }
        b.push(1);
        b.extend_from_slice(&(self.route.len() as u32).to_be_bytes());
        for r in &self.route {
            b.extend_from_slice(r);
        }
        b.extend_from_slice(&(self.extra.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.extra);
        b.extend_from_slice(&self.payload);
        b
    }
}

pub fn hex_id(id: &[u8; 6]) -> String {
    hex::encode_upper(id)
}

/// Our HelloMsgPayload, mirroring the phone's.
pub fn hello_payload(our_id: &str, name: &str) -> Vec<u8> {
    serde_json::json!({
        "mPayLoad": {
            "mDeviceIdBondMap": {"1": our_id},
            "mMprMode": 0,
            "mOnetId": our_id,
            "mDeviceName": name,
            "mLinkType": 16,
            "mLinkCost": 2,
            "mProtocol": 1
        },
        "mPayLoadType": 1
    })
    .to_string()
    .into_bytes()
}

/// Topics the PC subscribes to / publishes (DataBus pub/sub, `msg_topic_sync`).
pub const PC_SUB_TOPICS: &[&str] = &[
    "Oplus_PcConnect",
    "Oplus_HeySynergy_PcConnect_SyncNotification_Publisher",
    "Oplus_HeySynergy_PCConnect_Relay",
    "PcOneSpaceTopic",
    "DEVICEMGR_TOPIC",
    "Oplus_Cast",
    // pcAbility / phone_start_mirror (shared Mac/PC client path in linker).
    "Oplus_MacConnect",
];
pub const PC_PUB_TOPICS: &[&str] = &[
    "Oplus_PcConnect",
    "Oplus_HeySynergy_PcConnect_SyncNotification_Subscriber",
    "DEVICEMGR_TOPIC",
    "Oplus_HeySynergy_PadConnect_CastMaterial",
    "Oplus_Cast",
    "Oplus_MacConnect",
];

/// A `msg_normal_topic_data` DataBus publish (same envelope the phone uses).
pub fn topic_data(topic: &str, payload: &str, now_ms: u64) -> Vec<u8> {
    serde_json::json!({
        "dbs_msg_encrypt": true,
        "dbs_msg_from_device": "",
        "dbs_msg_id": "",
        "dbs_msg_payload": payload,
        "dbs_msg_priority": 100,
        "time": now_ms,
        "dbs_msg_to_device": "",
        "dbs_msg_topic": {"dbs_topic_name": topic, "dbs_topic_tag": 0},
        "dbs_msg_type": "msg_normal_topic_data"
    })
    .to_string()
    .into_bytes()
}

/// "Clipboard receiver ready": the phone's linker reads this relay list on
/// `Oplus_HeySynergy_PadConnect_CastMaterial` (`CastMaterialReadRunnable`),
/// starts FileShareEngine with IcdfStatus=Ready → sendClipToRemote → copyToClip.
pub fn clipboard_ready_relay(our_id: &str) -> String {
    serde_json::json!([
        {"key": "TaskType", "value": "ACROSS_DEVICE_CLIPBOARD"},
        {"key": "IcdfStatus", "value": "Ready"},
        {"key": "RemoteDvd", "value": our_id}
    ])
    .to_string()
}

/// Our `msg_topic_sync` (the phone sends the same JSON as router types 82 and 42).
pub fn topic_sync_payload(our_id: &str, now_ms: u64) -> Vec<u8> {
    let t = |n: &&str| serde_json::json!({"dbs_topic_name": n, "dbs_topic_tag": 0, "dbs_topic_qos": {"single_device_single_sub": "false"}});
    serde_json::json!({
        "dbs_msg_encrypt": true,
        "dbs_msg_from_device": our_id,
        "dbs_msg_id": "",
        "dbs_msg_payload": {
            "sub": PC_SUB_TOPICS.iter().map(t).collect::<Vec<_>>(),
            "pub": PC_PUB_TOPICS.iter().map(|n| serde_json::json!({"dbs_topic_name": n, "dbs_topic_tag": 0})).collect::<Vec<_>>()
        },
        "dbs_msg_priority": 100,
        "time": now_ms,
        "dbs_msg_to_device": "",
        "dbs_msg_type": "msg_topic_sync"
    })
    .to_string()
    .into_bytes()
}

/// DataBus header for an encrypted data message.
pub fn databus_header(msg_id: u16) -> [u8; 3] {
    let id = msg_id.to_be_bytes();
    [0x04, id[0], id[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decrypted hello from the phone, 2026-11-19.
    const HELLO: &str = "a1b2c3d4e5f6000001a193900bc1a1b2c3d4e5f64c494e5558010307010000000000ff000000ff000000ff01000000014c494e555801000000007b7d";

    #[test]
    fn parses_and_reencodes_real_hello_header() {
        let b = hex::decode(HELLO).unwrap();
        let m = RouterMsg::parse(&b).unwrap();
        assert_eq!(hex_id(&m.sender), "A1B2C3D4E5F6");
        assert_eq!(hex_id(&m.destination), "4C494E555801");
        assert_eq!(m.msg_type, MSG_HELLO);
        assert_eq!(m.version, 7);
        assert_eq!(m.route.len(), 1);
        assert_eq!(m.payload, b"{}");
        assert_eq!(m.encode(), b);
    }
}
