//! Service data sessions (e.g. the clipboard channel 104) and OPPO's
//! gRPC-over-OAF framing "ICDF" (`com.oplus.ocs.icdf.grpcchannel.inner.*`
//! in com.oplus.linker).
//!
//! Session frame body (TL mode 2 data session):
//!   u16 BE tlSeq ‖ u8 flags (0x04 = encrypted) ‖ payload
//! The receiver must ACK every tlSeq, or the phone retransmits:
//!   session header with ctrl bit set ‖ 0x01 (BLOCK_ACK) ‖ u16 seq  (`ta/m0.java n()`)
//! Encrypted payloads use a per-session [`AppCipher`] (counter per session+direction).
//!
//! ICDF frame: "ICDF" ‖ u32 len ‖ u16 streamId ‖ u8 cmd ‖ body   (len = 3 + body)
//!   data frames (cmd 8 client→server, 2 server→client): body = u32 seq ‖ u32 n ‖ n bytes protobuf
//!   15 rpc-method config · 7 stream head (u32 len + method, metadata, authority)
//!   9 half-close · 10 cancel (client→server) · 3 close (u8 status ‖ u32 trailerCount) · 4 cancel

use std::collections::HashMap;

use super::epi::AppCipher;

pub const MAGIC: &[u8; 4] = b"ICDF";

pub const CMD_SERVER_DATA_TO_CLIENT: u8 = 2;
pub const CMD_CLOSE_TO_CLIENT: u8 = 3;
pub const CMD_HEAD: u8 = 7;
pub const CMD_DATA_TO_SERVER: u8 = 8;
pub const CMD_HALF_CLOSE: u8 = 9;
pub const CMD_CANCEL: u8 = 10;
pub const CMD_RPC_CONFIG: u8 = 15;

pub fn frame(stream: u16, cmd: u8, body: &[u8]) -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.extend_from_slice(&((3 + body.len()) as u32).to_be_bytes());
    b.extend_from_slice(&stream.to_be_bytes());
    b.push(cmd);
    b.extend_from_slice(body);
    b
}

pub fn data_frame(stream: u16, cmd: u8, seq: u32, msg: &[u8]) -> Vec<u8> {
    let mut body = seq.to_be_bytes().to_vec();
    body.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    body.extend_from_slice(msg);
    frame(stream, cmd, &body)
}

/// Session header with the control bit set (`i.z(ctrl=1, frag=0)`).
pub fn ack_frame(session: u16, seq: u16) -> Vec<u8> {
    let mut b = vec![0x10 | ((session >> 6) & 0x0f) as u8, ((session & 63) << 2) as u8];
    b.push(1); // AFP_CONTROL_FRAME_BLOCK_ACK
    b.extend_from_slice(&seq.to_be_bytes());
    b
}

/// What a decoded ICDF frame asks us to do.
#[derive(Debug)]
pub enum Event {
    Config(String),
    Head { stream: u16, method: String },
    Data { stream: u16, seq: u32, msg: Vec<u8> },
    HalfClose { stream: u16 },
    Cancel { stream: u16 },
    Other { stream: u16, cmd: u8, body: Vec<u8> },
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

pub fn parse_frame(f: &[u8]) -> Option<Event> {
    if f.len() < 11 || &f[..4] != MAGIC {
        return None;
    }
    let stream = u16::from_be_bytes([f[8], f[9]]);
    let cmd = f[10];
    let body = &f[11..];
    Some(match cmd {
        CMD_RPC_CONFIG => {
            // u32 count, per method: u32 len, name, u16 type, u16 channel, u32 flags, u32 0
            let mut names = vec![];
            let n = be32(body, 0).unwrap_or(0);
            let mut i = 4;
            for _ in 0..n {
                let Some(l) = be32(body, i) else { break };
                let Some(end) = (i + 4).checked_add(l as usize).filter(|&e| e <= body.len()) else { break };
                let name = String::from_utf8_lossy(&body[i + 4..end]).to_string();
                let rest = body.get(end..end + 12).unwrap_or_default();
                names.push(format!("{name} (type/channel/flags {})", hex::encode(rest)));
                i = end + 12;
            }
            Event::Config(names.join(", "))
        }
        CMD_HEAD => {
            let l = be32(body, 0).unwrap_or(0) as usize;
            Event::Head { stream, method: String::from_utf8_lossy(body.get(4..4usize.saturating_add(l)).unwrap_or_default()).to_string() }
        }
        CMD_DATA_TO_SERVER => {
            let seq = be32(body, 0).unwrap_or(0);
            let n = be32(body, 4).unwrap_or(0) as usize;
            Event::Data { stream, seq, msg: body.get(8..8usize.saturating_add(n)).unwrap_or_default().to_vec() }
        }
        CMD_HALF_CLOSE => Event::HalfClose { stream },
        CMD_CANCEL => Event::Cancel { stream },
        _ => Event::Other { stream, cmd, body: body.to_vec() },
    })
}

/// Minimal protobuf reader for `ClipData { bytes data = 1; int32 feature = 2; repeated UriRawInfo = 3; }`.
pub fn parse_clip_data(m: &[u8]) -> (Vec<u8>, i64, usize) {
    let (mut data, mut feature, mut uris) = (vec![], 0i64, 0usize);
    let mut i = 0;
    let varint = |i: &mut usize| -> Option<u64> {
        let mut v = 0u64;
        for s in 0..10 {
            let b = *m.get(*i)?;
            *i += 1;
            v |= ((b & 0x7f) as u64) << (7 * s);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    };
    while i < m.len() {
        let Some(key) = varint(&mut i) else { break };
        match (key >> 3, key & 7) {
            (_, 0) => {
                let v = varint(&mut i).unwrap_or(0);
                if key >> 3 == 2 {
                    feature = v as i64;
                }
            }
            (f, 2) => {
                let l = varint(&mut i).unwrap_or(0) as usize;
                let v = m.get(i..i.saturating_add(l)).unwrap_or_default().to_vec();
                i = i.saturating_add(l);
                match f {
                    1 => data = v,
                    3 => uris += 1,
                    _ => {}
                }
            }
            _ => break,
        }
    }
    (data, feature, uris)
}

/// `FileData { string info=1; sint64 length=2; bytes buffer=3; int64 flag=4; string uri=5; }`
#[derive(Debug, Default)]
pub struct FileData {
    pub info: String,
    pub length: i64,
    pub buffer: Vec<u8>,
    pub flag: i64,
    pub uri: String,
}

pub fn parse_file_data(m: &[u8]) -> FileData {
    let mut f = FileData::default();
    let mut i = 0;
    let varint = |i: &mut usize| -> Option<u64> {
        let mut v = 0u64;
        for s in 0..10 {
            let b = *m.get(*i)?;
            *i += 1;
            v |= ((b & 0x7f) as u64) << (7 * s);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    };
    while i < m.len() {
        let Some(key) = varint(&mut i) else { break };
        match (key >> 3, key & 7) {
            (n, 0) => {
                let v = varint(&mut i).unwrap_or(0);
                match n {
                    2 => f.length = ((v >> 1) as i64) ^ -((v & 1) as i64), // sint64 zigzag
                    4 => f.flag = v as i64,
                    _ => {}
                }
            }
            (n, 2) => {
                let l = varint(&mut i).unwrap_or(0) as usize;
                let v = m.get(i..i.saturating_add(l)).unwrap_or_default();
                i = i.saturating_add(l);
                match n {
                    1 => f.info = String::from_utf8_lossy(v).to_string(),
                    3 => f.buffer = v.to_vec(),
                    5 => f.uri = String::from_utf8_lossy(v).to_string(),
                    _ => {}
                }
            }
            _ => break,
        }
    }
    f
}

/// `FileStatus { int32 status=1; int64 length=2; }`
pub fn file_status_proto(status: i32, length: i64) -> Vec<u8> {
    let mut v = vec![];
    let mut put = |tag: u8, mut n: u64| {
        v.push(tag);
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                v.push(b);
                break;
            }
            v.push(b | 0x80);
        }
    };
    put(0x08, status as u64);
    put(0x10, length as u64);
    v
}

/// A file being received over `FileService/writeFile`.
pub struct FileRecv {
    pub path: std::path::PathBuf,
    pub file: std::fs::File,
    pub total: i64,
    pub written: i64,
}

/// Where received files go: ~/Downloads/Olink/
pub fn download_dir() -> std::path::PathBuf {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_else(|| ".".into());
    home.join("Downloads").join("Olink")
}

/// Bidi overrides and zero-width characters: they let a name like
/// "invoice\u{202e}fdp.exe" display as "invoiceexe.pdf".
fn is_invisible_format(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}

/// Safe file name from the phone's `info` path, de-duplicated in `dir`.
pub fn target_path(dir: &std::path::Path, info: &str) -> std::path::PathBuf {
    let base = info.rsplit(['/', '\\']).next().unwrap_or("").trim();
    let base: String = base.chars().filter(|&c| !c.is_control() && c != '/' && c != '\\' && !is_invisible_format(c)).collect();
    let base = if base.is_empty() || base == "." || base == ".." { "received-file".to_string() } else { base };
    let mut p = dir.join(&base);
    let (stem, ext) = match base.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (base.clone(), String::new()),
    };
    let mut n = 1;
    while p.exists() {
        p = dir.join(format!("{stem} ({n}){ext}"));
        n += 1;
    }
    p
}

/// Largest ICDF frame we reassemble.
const MAX_FRAME: usize = 8 << 20;

/// Per data-session state.
pub struct SessionState {
    pub cipher: AppCipher,
    pub tx_seq: u16,
    pub buf: Vec<u8>,
    pub methods: HashMap<u16, String>,
    pub files: HashMap<u16, FileRecv>,
}

impl SessionState {
    pub fn new(cipher: AppCipher) -> Self {
        Self { cipher, tx_seq: 0, buf: vec![], methods: HashMap::new(), files: HashMap::new() }
    }

    /// Wrap an ICDF frame for sending on `session`: tlSeq ‖ 0x04 ‖ encrypted.
    pub fn wrap(&mut self, session: u16, icdf: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.tx_seq = self.tx_seq.wrapping_add(1).max(1);
        let mut body = self.tx_seq.to_be_bytes().to_vec();
        body.push(0x04);
        body.extend_from_slice(&self.cipher.encrypt(icdf)?);
        Ok(super::epi::session_frame(session, &body))
    }

    /// Feed a decrypted payload; returns complete ICDF frames.
    pub fn feed(&mut self, plain: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(plain);
        let mut out = vec![];
        loop {
            if self.buf.len() < 8 {
                break;
            }
            if &self.buf[..4] != MAGIC {
                // Lost sync: drop everything (logged by the caller).
                out.push(std::mem::take(&mut self.buf));
                break;
            }
            let len = u32::from_be_bytes(self.buf[4..8].try_into().unwrap()) as usize;
            if len > MAX_FRAME {
                // A frame this big never comes from the phone (it uses 400 KB
                // chunks); don't buffer towards it.
                out.push(std::mem::take(&mut self.buf));
                break;
            }
            if self.buf.len() < 8 + len {
                break;
            }
            out.push(self.buf.drain(..8 + len).collect());
        }
        out
    }
}

/// Put text on the desktop clipboard (Wayland `wl-copy`, else X11 `xclip`).
pub fn set_desktop_clipboard(text: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .spawn()
        .or_else(|_| Command::new("xclip").args(["-selection", "clipboard"]).stdin(Stdio::piped()).spawn())?;
    child.stdin.take().ok_or_else(|| anyhow::anyhow!("no stdin"))?.write_all(text.as_bytes())?;
    // Reap it once it exits (wl-copy forks its server off), so no zombies pile up.
    std::thread::spawn(move || child.wait());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The phone's first decrypted frame on the clipboard channel (2026-11-19).
    #[test]
    fn parses_real_rpc_config() {
        let f = hex::decode("494344460000003200000f000000010000001b436c6970426f617264536572766963652f636f7079546f436c6970000100680000000200000000").unwrap();
        match parse_frame(&f).unwrap() {
            Event::Config(s) => assert!(s.starts_with("ClipBoardService/copyToClip"), "{s}"),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn ack_header() {
        let a = ack_frame(452, 1);
        assert_eq!(a, vec![0x17, 0x10, 0x01, 0x00, 0x01]);
        let (sid, ctrl, _, _) = super::super::epi::parse_session_frame(&a).unwrap();
        assert_eq!((sid, ctrl), (452, 1));
    }

    #[test]
    fn file_data_and_names() {
        // FileData { info: "a/b.jpg", length: 3 (zigzag 6), buffer: [1,2,3,0,0], flag: 0 }
        let m = [0x0a, 7, b'a', b'/', b'b', b'.', b'j', b'p', b'g', 0x10, 6, 0x1a, 5, 1, 2, 3, 0, 0];
        let f = parse_file_data(&m);
        assert_eq!((f.info.as_str(), f.length, f.buffer.len()), ("a/b.jpg", 3, 5));
        let d = std::env::temp_dir();
        assert!(target_path(&d, "../../etc/passwd").starts_with(&d));
        assert_eq!(target_path(&d, "invoice\u{202e}fdp.exe").file_name().unwrap(), "invoicefdp.exe");
        assert_eq!(target_path(&d, "").file_name().unwrap(), "received-file");
    }

    #[test]
    fn hostile_lengths_dont_panic() {
        // Field 1 with a length near u64::MAX.
        let (d, _, _) = parse_clip_data(&[0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(d.is_empty());
        let f = parse_file_data(&[0x1a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(f.buffer.is_empty());
        let mut cfg = frame(1, CMD_RPC_CONFIG, &[0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff]);
        cfg.extend_from_slice(b"x");
        assert!(parse_frame(&cfg).is_some());
        let mut st = SessionState::new(super::super::epi::AppCipher::new(&[0; 16], [0; 8], [0; 8]));
        let huge = [b"ICDF".as_slice(), &[0xff, 0xff, 0xff, 0xff]].concat();
        assert_eq!(st.feed(&huge).len(), 1); // dropped, not buffered towards 4 GB
        assert!(st.buf.is_empty());
    }

    #[test]
    fn clip_data_roundtrip() {
        // ClipData { data: "hi", feature: 1 }
        let (d, f, u) = parse_clip_data(&[0x0a, 2, b'h', b'i', 0x10, 1]);
        assert_eq!((d.as_slice(), f, u), (&b"hi"[..], 1, 0));
    }
}
