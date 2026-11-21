//! O+ Connect control-message types and wire codec.
//!
//! Every constant and field name in this file was recovered statically from
//! `OShareTransferSDK.dll` (a .NET Framework 4.6 assembly) — classes
//! `WebSocketMessage`, `HttpMessage`, `JsonUtils`, `OShareConstant`, and the
//! `TransferFile` / `DownloadRequest` data types. They are reproduced here in
//! Rust so a Linux client can speak the same protocol.
//!
//! Control messages travel as WebSocket **text** frames whose payload is a
//! string of the form:
//!
//! ```text
//!     <kind>:<id>:<taskName>?<json>
//!     e.g.  action:0:sendRequest?{"taskId":"...", ...}
//!           ack:0:downloadRequest?{"files":[...], ...}
//! ```
//!
//! `kind` is `action` or `ack`; `id` is the message id; `taskName` is one of
//! the task types below; everything after the `?` (the original `MASK`
//! character) is the JSON command body.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The separator and mask characters used by `WebSocketMessage` on the wire.
pub const COLON: char = ':';
pub const MASK: char = '?';

/// `WebSocketMessage` protocol-version constants.
pub mod version {
    /// `LOCAL_VERSION` — the version this implementation speaks.
    pub const LOCAL: i32 = 4;
    /// `BIG_MESSAGE_VERSION` — minimum peer version for the /bigmessage path.
    pub const BIG_MESSAGE: i32 = 3;
    /// `DOWNLOAD_REQUEST_BIG_MESSAGE_VERSION`.
    pub const DOWNLOAD_REQUEST_BIG_MESSAGE: i32 = 4;
    /// `BIG_MESSAGE_MIN_BYTES` — control payloads larger than this are fetched
    /// over HTTP via `/bigmessage` instead of being sent inline.
    pub const BIG_MESSAGE_MIN_BYTES: usize = 8192;
    /// `DEAULT_PHONE_VERSION` [sic] — assumed peer version before negotiation.
    pub const DEFAULT_PHONE: i32 = 2;
    /// JSON key carrying the negotiated protocol version.
    pub const PROTOCOL_VERSION_KEY: &str = "protocolVersion";
}

/// `WebSocketMessage` status codes (the `type` field of a `status` message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    Success = 1,
    Failure = 2,
    Cancel = 3,
    Timeout = 4,
    FileCancel = 100,
    FileSuccess = 101,
}

impl Status {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn from_code(code: i32) -> Option<Self> {
        Some(match code {
            1 => Status::Success,
            2 => Status::Failure,
            3 => Status::Cancel,
            4 => Status::Timeout,
            100 => Status::FileCancel,
            101 => Status::FileSuccess,
            _ => return None,
        })
    }
}

/// Human-readable `reason` strings used alongside `cancel` / `status`.
/// (From `WebSocketMessage.REASON_*`.)
pub mod reason {
    pub const FAILURE_CANNOT_ACCESS: &str = "cannot access";
    pub const FAILURE_FILE_NOT_FOUND: &str = "file not found";
    pub const FAILURE_NO_RESPONSE: &str = "no response";
    pub const FAILURE_CONNECTION_LOST: &str = "connection lost";
    pub const CANCEL_REFUSE: &str = "user refuse";
    pub const CANCEL_INTERRUPT: &str = "user interrupt";
    pub const CANCEL_TIMEOUT: &str = "timeout";
    pub const CANCEL_NO_SPACE: &str = "no enough space";
    pub const CANCEL_REPEAT_SEND: &str = "repeat send";
    pub const NO_PHONE_SPACE: &str = "NO_PHONE_SPACE";
    pub const NO_MAC_SPACE: &str = "NO_MAC_SPACE";
    pub const CANCEL_OTHER: &str = "OTHER";
    // The "_RUST" variants below are the tokens the phone-side Rust layer emits.
    pub const CANCEL_REFUSE_RUST: &str = "REFUSE";
    pub const CANCEL_INTERRUPT_RUST: &str = "INTERRUPT";
    pub const LOCAL_CANCEL_FAILED: &str = "LOCAL_CANCEL_FAILED";
}

/// The task type carried in a control message (`WebSocketMessage` task names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskName {
    /// Offer files to the peer.
    SendRequest,
    /// Ask to pull offered files.
    DownloadRequest,
    /// Abort a task or a single file.
    Cancel,
    /// Progress / result updates.
    Status,
    /// Exchange protocol versions.
    VersionNegotiation,
}

impl TaskName {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskName::SendRequest => "sendRequest",
            TaskName::DownloadRequest => "downloadRequest",
            TaskName::Cancel => "cancel",
            TaskName::Status => "status",
            TaskName::VersionNegotiation => "versionNegotiation",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "sendRequest" => TaskName::SendRequest,
            "downloadRequest" => TaskName::DownloadRequest,
            "cancel" => TaskName::Cancel,
            "status" => TaskName::Status,
            "versionNegotiation" => TaskName::VersionNegotiation,
            _ => return None,
        })
    }
}

/// `action` packets drive the peer; `ack` packets acknowledge an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    Action,
    Ack,
}

impl EnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EnvelopeKind::Action => "action",
            EnvelopeKind::Ack => "ack",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "action" => Some(EnvelopeKind::Action),
            "ack" => Some(EnvelopeKind::Ack),
            _ => None,
        }
    }
}

/// A decoded control message: `<kind>:<id>:<task>?<json>`.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub kind: EnvelopeKind,
    pub id: i32,
    pub task: TaskName,
    pub body: Value,
}

impl Envelope {
    pub fn new(kind: EnvelopeKind, id: i32, task: TaskName, body: Value) -> Self {
        Self { kind, id, task, body }
    }

    /// Serialize to the on-wire text form `<kind>:<id>:<task>?<json>`.
    pub fn encode(&self) -> String {
        format!(
            "{}{COLON}{}{COLON}{}{MASK}{}",
            self.kind.as_str(),
            self.id,
            self.task.as_str(),
            self.body
        )
    }

    /// Parse a text frame. Mirrors `WebSocketMessage.getArgsString`, which
    /// splits on the first two `:` and the `?` mask.
    pub fn parse(frame: &str) -> Result<Self, MessageError> {
        let (head, json) = frame
            .split_once(MASK)
            .ok_or(MessageError::MissingMask)?;
        let mut parts = head.splitn(3, COLON);
        let kind = parts.next().ok_or(MessageError::Malformed)?;
        let id = parts.next().ok_or(MessageError::Malformed)?;
        let task = parts.next().ok_or(MessageError::Malformed)?;

        let kind = EnvelopeKind::parse(kind).ok_or(MessageError::UnknownKind)?;
        let id: i32 = id.parse().map_err(|_| MessageError::Malformed)?;
        let task = TaskName::parse(task).ok_or(MessageError::UnknownTask)?;
        let body: Value = if json.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(json).map_err(MessageError::Json)?
        };

        Ok(Envelope { kind, id, task, body })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("control frame missing '?' mask")]
    MissingMask,
    #[error("control frame is malformed")]
    Malformed,
    #[error("unknown envelope kind")]
    UnknownKind,
    #[error("unknown task name")]
    UnknownTask,
    #[error("invalid JSON body: {0}")]
    Json(#[from] serde_json::Error),
}

/// One file in a transfer. Field names verified against real traffic in
/// `ovmsocketlog.log`; the wire uses `isFolder` (the SDK class field was
/// `isfolder`, so we accept both). Most fields default because the `send` and
/// `download` directions include different subsets.
///
/// Example `file[]` entry (phone -> PC):
/// ```json
/// {"name":"IMG20260101120000.jpg","size":5843203,"mimeType":"image/jpeg",
///  "fileId":"68944f59-...","filePath":"/storage/emulated/0/DCIM/Camera/IMG...jpg",
///  "isFolder":false}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransferFile {
    #[serde(rename = "fileId", default)]
    pub file_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub size: i64,
    #[serde(rename = "mimeType", default)]
    pub mime_type: String,
    /// Source path on the sender (e.g. `/storage/emulated/0/DCIM/...` on Android).
    #[serde(rename = "filePath", default)]
    pub file_path: String,
    #[serde(rename = "isFolder", alias = "isfolder", default)]
    pub is_folder: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(rename = "createTime", default, skip_serializing_if = "Option::is_none")]
    pub create_time: Option<i64>,
    #[serde(rename = "targetPath", default, skip_serializing_if = "String::is_empty")]
    pub target_path: String,
}

/// A `downloadRequest` / offer body. CAPTURE-VERIFIED shape — this is what the
/// phone sends when it offers a file (the PC replies `ack:0:downloadRequest?...`):
///
/// ```json
/// {"taskId":"0d668e0d-...","senderId":"A1B2C3D4E5F6i1Tx","senderName":"MYPHONE",
///  "fileName":"IMG20260101120000.jpg","mimeType":"image/jpeg","fileCount":1,
///  "totalSize":5843203,"thumbnail":"/thumbnail?taskId=0d668e0d-...",
///  "thumbnail_height":320,"thumbnail_width":320,
///  "file":[ { ...TransferFile... } ]}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DownloadFileInfo {
    #[serde(rename = "taskId")]
    pub task_id: String,
    #[serde(rename = "senderId", default)]
    pub sender_id: String,
    #[serde(rename = "senderName", default)]
    pub sender_name: String,
    #[serde(rename = "fileName", default)]
    pub file_name: String,
    #[serde(rename = "mimeType", default)]
    pub mime_type: String,
    #[serde(rename = "fileCount", default)]
    pub file_count: i32,
    #[serde(rename = "totalSize", default)]
    pub total_size: i64,
    /// Relative thumbnail URL, e.g. `/thumbnail?taskId=...`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub thumbnail: String,
    #[serde(rename = "thumbnail_height", default)]
    pub thumbnail_height: i32,
    #[serde(rename = "thumbnail_width", default)]
    pub thumbnail_width: i32,
    /// NB: the wire key is the singular `file`, not `files`.
    #[serde(rename = "file", default)]
    pub files: Vec<TransferFile>,
}

/// When a control payload is large, the sender does NOT inline the file list.
/// It sends this pointer and the peer fetches the real body from
/// `/bigmessage?taskId=<taskId>&messageId=<messageId>`. CAPTURE-VERIFIED:
///
/// ```json
/// {"isMessageSend":"true","messageId":"c0838289d13d4a40b89aaae7df904efe",
///  "taskId":"1869b34a-67aa-4dbd-9c77-7074234d8901"}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BigMessagePointer {
    /// String `"true"` on the wire, not a JSON boolean.
    #[serde(rename = "isMessageSend")]
    pub is_message_send: String,
    /// 32-char hex id used as `messageId` in the `/bigmessage` URL.
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "taskId")]
    pub task_id: String,
}

/// A `status` body. Matches `StateInfo` + `JsonUtils.createStatusJson`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusInfo {
    #[serde(rename = "taskId")]
    pub task_id: String,
    #[serde(rename = "type")]
    pub kind: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(rename = "fileId", default, skip_serializing_if = "String::is_empty")]
    pub file_id: String,
}

/// Build a `status` JSON body (`JsonUtils.createStatusJson`).
pub fn status_json(task_id: &str, status: Status, reason: Option<&str>) -> Value {
    serde_json::json!({
        "taskId": task_id,
        "type": status.code(),
        "reason": reason.unwrap_or(""),
    })
}

/// Build a `versionNegotiation` JSON body (`JsonUtils.createVersionJson`).
pub fn version_json(version: i32, protocol_version: i32) -> Value {
    serde_json::json!({
        "version": version,
        "protocolVersion": protocol_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_envelope() {
        let body = serde_json::json!({ "taskId": "t1", "type": 1 });
        let env = Envelope::new(EnvelopeKind::Action, 0, TaskName::Status, body.clone());
        let wire = env.encode();
        assert!(wire.starts_with("action:0:status?"));

        let back = Envelope::parse(&wire).expect("parse");
        assert_eq!(back.kind, EnvelopeKind::Action);
        assert_eq!(back.id, 0);
        assert_eq!(back.task, TaskName::Status);
        assert_eq!(back.body, body);
    }

    #[test]
    fn parse_known_frames() {
        // Frames observed in the SDK's onReceiverPacketMessage logging.
        let a = Envelope::parse("action:0:sendRequest?{}").unwrap();
        assert_eq!(a.task, TaskName::SendRequest);
        let b = Envelope::parse("ack:0:downloadRequest?{\"files\":[]}").unwrap();
        assert_eq!(b.kind, EnvelopeKind::Ack);
        assert_eq!(b.task, TaskName::DownloadRequest);
    }

    /// The full phone -> PC offer exactly as captured in PROTOCOL.md §2.
    const CAPTURED_OFFER: &str = r#"action:0:downloadRequest?{"taskId":"0d668e0d-de55-40ef-b4f9-58a4b0694652","senderId":"A1B2C3D4E5F6i1Tx","senderName":"MYPHONE","fileName":"IMG20260101120000.jpg","mimeType":"image/jpeg","fileCount":1,"totalSize":5843203,"thumbnail":"/thumbnail?taskId=0d668e0d-de55-40ef-b4f9-58a4b0694652","thumbnail_height":320,"thumbnail_width":320,"file":[{"name":"IMG20260101120000.jpg","size":5843203,"mimeType":"image/jpeg","fileId":"68944f59-eb0c-4b08-977d-e188ca4347b3","filePath":"/storage/emulated/0/DCIM/Camera/IMG20260101120000.jpg","isFolder":false}]}"#;

    #[test]
    fn captured_offer_decodes_and_roundtrips() {
        let env = Envelope::parse(CAPTURED_OFFER).expect("parse captured offer");
        assert_eq!(env.kind, EnvelopeKind::Action);
        assert_eq!(env.task, TaskName::DownloadRequest);

        let info: DownloadFileInfo = serde_json::from_value(env.body.clone()).expect("decode offer");
        assert_eq!(info.task_id, "0d668e0d-de55-40ef-b4f9-58a4b0694652");
        assert_eq!(info.sender_id, "A1B2C3D4E5F6i1Tx");
        assert_eq!(info.file_count, 1);
        assert_eq!(info.total_size, 5_843_203);
        assert_eq!(info.files.len(), 1);
        let f = &info.files[0];
        assert_eq!(f.file_id, "68944f59-eb0c-4b08-977d-e188ca4347b3");
        assert_eq!(f.size, 5_843_203);
        assert!(!f.is_folder);

        // Re-encode: must reproduce the exact wire JSON (singular `file`, `isFolder`).
        let re = serde_json::to_value(&info).unwrap();
        assert_eq!(re, env.body, "offer must re-encode to the captured JSON");
        let wire = Envelope::new(EnvelopeKind::Action, 0, TaskName::DownloadRequest, re).encode();
        assert_eq!(Envelope::parse(&wire).unwrap().body, env.body);
    }

    #[test]
    fn captured_bigmessage_pointer() {
        let body = r#"{"isMessageSend":"true","messageId":"c0838289d13d4a40b89aaae7df904efe","taskId":"1869b34a-67aa-4dbd-9c77-7074234d8901"}"#;
        let p: BigMessagePointer = serde_json::from_str(body).unwrap();
        assert_eq!(p.is_message_send, "true");
        assert_eq!(p.message_id, "c0838289d13d4a40b89aaae7df904efe");
        let back = serde_json::to_value(&p).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(body).unwrap());
    }

    #[test]
    fn captured_version_and_acks() {
        let v = Envelope::parse(r#"action:0:versionNegotiation?{"version":2,"protocolVersion":4}"#).unwrap();
        assert_eq!(v.task, TaskName::VersionNegotiation);
        assert_eq!(v.body, version_json(2, 4));

        let a = Envelope::parse(r#"ack:0:sendRequest?{"taskId":"1869b34a-67aa-4dbd-9c77-7074234d8901"}"#).unwrap();
        assert_eq!((a.kind, a.task), (EnvelopeKind::Ack, TaskName::SendRequest));
        let s = Envelope::parse(r#"ack:0:status?{"taskId":"1005444519"}"#).unwrap();
        assert_eq!(s.task, TaskName::Status);
    }

    #[test]
    fn status_codes_roundtrip() {
        for code in [1, 2, 3, 4, 100, 101] {
            let st = Status::from_code(code).expect("known status code");
            assert_eq!(st.code(), code);
        }
        assert!(Status::from_code(999).is_none());
    }
}
