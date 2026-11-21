//! PC → phone clipboard: the PC plays the role the phone plays for phone → PC.
//!
//! 1. Watch the desktop clipboard (`wl-paste`, else `xclip`), ignoring text we
//!    just received from the phone.
//! 2. Learn the phone's `app:clipboardservice` *provider* agent via CapEx.
//! 3. Tell the phone via the CastMaterial relay (`IcdfStatus=Init`); it answers
//!    `IcdfStatus=Ready` on `Oplus_PcConnect` (we also proceed after a timeout).
//! 4. Open a service connection (session 1, type 1) to that agent for channels
//!    104/110, then on the 104 session act as the ICDF/gRPC *client*:
//!    config(15) → head(7, "ClipBoardService/copyToClip") → data(8, ClipData) → half-close(9).
//!    The phone (ClipBoardServiceImpl) answers data(2, Result) + close(3) and
//!    puts `ClipData.data` (feature 0 = UTF-8 text) on its clipboard.

use std::sync::Mutex;

use super::icdf;

pub const METHOD: &str = "ClipBoardService/copyToClip";
pub const PROFILE: &str = "app:clipboardservice";

/// Text most recently put on (or seen on) the desktop clipboard by us, so the
/// watcher doesn't bounce phone text straight back to the phone.
pub static LAST_CLIP: Mutex<String> = Mutex::new(String::new());

pub fn note_clip(text: &str) {
    *LAST_CLIP.lock().unwrap_or_else(|p| p.into_inner()) = text.to_string();
}

/// Read the desktop clipboard as text (None if empty/unavailable).
pub fn read_desktop_clipboard() -> Option<String> {
    let out = std::process::Command::new("wl-paste")
        .args(["-n", "-t", "text"])
        .output()
        .or_else(|_| std::process::Command::new("xclip").args(["-selection", "clipboard", "-o"]).output())
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    (!s.is_empty()).then_some(s)
}

/// Password managers (KeePassXC, KWallet, …) mark copied secrets with this
/// type (KDE's convention, also honoured by clipboard managers).
const SECRET_HINT: &str = "x-kde-passwordManagerHint";

/// Whether the current clipboard content is marked as a password.
fn clipboard_is_secret() -> bool {
    let out = std::process::Command::new("wl-paste")
        .arg("--list-types")
        .output()
        .or_else(|_| std::process::Command::new("xclip").args(["-selection", "clipboard", "-o", "-t", "TARGETS"]).output());
    out.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.trim() == SECRET_HINT))
}

/// Watch the desktop clipboard while a phone is connected; send new text
/// (not from the phone) on `tx`. Skipped: passwords from password managers,
/// and everything while clipboard sharing is off in the settings.
///
/// On Wayland this is event-driven: one `wl-paste --watch echo` runs `echo`
/// on each clipboard change, so we wake only when something is copied (no
/// polling). Elsewhere (X11) we fall back to polling. Ends, and stops the
/// helper, when the phone disconnects (`tx` closes).
pub fn spawn_watcher(tx: tokio::sync::mpsc::UnboundedSender<String>) {
    tokio::spawn(async move {
        if let Some(cur) = tokio::task::spawn_blocking(read_desktop_clipboard).await.ok().flatten() {
            note_clip(&cur); // don't send whatever was there before we connected
        }
        let watcher = tokio::process::Command::new("wl-paste")
            .args(["--watch", "echo"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        match watcher {
            Ok(mut child) => {
                use tokio::io::AsyncBufReadExt;
                let Some(out) = child.stdout.take() else { return };
                let mut changes = tokio::io::BufReader::new(out).lines();
                loop {
                    tokio::select! {
                        line = changes.next_line() => match line {
                            Ok(Some(_)) => {
                                if !check_clipboard(&tx).await {
                                    return;
                                }
                            }
                            _ => return, // wl-paste ended (no data-control support?)
                        },
                        _ = tx.closed() => return, // phone gone: `child` is dropped and killed
                    }
                }
            }
            Err(_) => loop {
                tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                if tx.is_closed() || !check_clipboard(&tx).await {
                    return;
                }
            },
        }
    });
}

/// Read the clipboard and send it if it's new and may go to the phone.
/// Returns false once the phone connection is gone.
async fn check_clipboard(tx: &tokio::sync::mpsc::UnboundedSender<String>) -> bool {
    let Some(cur) = tokio::task::spawn_blocking(read_desktop_clipboard).await.ok().flatten() else { return true };
    let changed = {
        let mut last = LAST_CLIP.lock().unwrap_or_else(|p| p.into_inner());
        if *last != cur {
            *last = cur.clone();
            true
        } else {
            false
        }
    };
    // Noted above either way, so turning sharing back on later doesn't send
    // what was copied while it was off.
    if !changed || !crate::settings::get().share_clipboard {
        return true;
    }
    if tokio::task::spawn_blocking(clipboard_is_secret).await.unwrap_or(true) {
        println!("  (clipboard holds a password-manager secret; not sent to the phone)");
        return true;
    }
    tx.send(cur).is_ok()
}

/// CapEx query for specific profiles (type 1, queryType 3, u32 0, count, "id;"...).
pub fn capex_query_for(profiles: &[&str]) -> Vec<u8> {
    super::epi::capex_sync_query(profiles)
}

/// Parse a CapEx response body: (appName, agentId, profileId, role) for each agent.
pub fn parse_capex_response(b: &[u8]) -> Vec<(String, u16, String, u8)> {
    let mut out = vec![];
    if b.len() < 4 || b[0] != 2 {
        return out;
    }
    let mut i = 2 + if b[1] == 2 || b[1] == 3 { 4 } else { 0 };
    let rd16 = |i: usize| b.get(i..i + 2).map(|x| u16::from_be_bytes([x[0], x[1]]));
    let rdstr = |i: &mut usize| -> Option<String> {
        let end = b.get(*i..)?.iter().position(|&c| c == b';')? + *i;
        let s = String::from_utf8_lossy(&b[*i..end]).to_string();
        *i = end + 1;
        Some(s)
    };
    let Some(n) = rd16(i) else { return out };
    i += 2;
    for _ in 0..n {
        let Some(app) = rdstr(&mut i) else { return out };
        let Some(_app2) = rdstr(&mut i) else { return out };
        let Some(na) = rd16(i) else { return out };
        i += 2;
        for _ in 0..na {
            let Some(agent) = rd16(i) else { return out };
            i += 2;
            if b.get(i) == Some(&b'=') {
                // compact 17-byte profile form; not expected from phones
                return out;
            }
            let Some(profile) = rdstr(&mut i) else { return out };
            let role = b.get(i + 2).copied().unwrap_or(0);
            i += 2 + 1 + 2; // version, role, connTimeout
            out.push((app.clone(), agent, profile, role));
        }
    }
    out
}

/// Service connection REQUEST from us (sender view: remote = phone, local = us).
pub fn service_conn_request(phone_agent: u16, our_agent: u16, sessions: &[u16], channels: &[u16]) -> Vec<u8> {
    service_conn_request_for(PROFILE, phone_agent, our_agent, sessions, channels)
}

pub fn service_conn_request_for(profile: &str, phone_agent: u16, our_agent: u16, sessions: &[u16], channels: &[u16]) -> Vec<u8> {
    let mut b = vec![1];
    b.extend_from_slice(&phone_agent.to_be_bytes());
    b.extend_from_slice(&our_agent.to_be_bytes());
    b.extend_from_slice(profile.as_bytes());
    b.push(b';');
    b.extend_from_slice(&(sessions.len() as u16).to_be_bytes());
    for s in sessions {
        b.extend_from_slice(&s.to_be_bytes());
    }
    for c in channels {
        b.extend_from_slice(&c.to_be_bytes());
    }
    // qos (type, class) per channel, as the phone sends for 104/110
    for (k, _) in channels.iter().enumerate() {
        b.extend_from_slice(if k == 0 { &[5, 1] } else { &[4, 1] });
    }
    for _ in channels {
        b.push(0); // payloadType
    }
    b
}

fn lenpref(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

/// ICDF rpc-method config (stream 0, cmd 15), like `GrpcClientAdapter` sends.
pub fn icdf_config() -> Vec<u8> {
    let mut p = 1u32.to_be_bytes().to_vec();
    p.extend_from_slice(&lenpref(METHOD.as_bytes()));
    p.extend_from_slice(&1u16.to_be_bytes()); // type
    p.extend_from_slice(&104u16.to_be_bytes()); // channel
    p.extend_from_slice(&2u32.to_be_bytes()); // flags: encrypt
    p.extend_from_slice(&0u32.to_be_bytes());
    icdf::frame(0, icdf::CMD_RPC_CONFIG, &p)
}

/// Stream head (cmd 7): method, metadata (count 0), authority ("").
pub fn icdf_head(stream: u16) -> Vec<u8> {
    let mut p = lenpref(METHOD.as_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    icdf::frame(stream, icdf::CMD_HEAD, &p)
}

/// `ClipData { data = text }` (feature 0 = plain text).
pub fn clip_data_proto(text: &str) -> Vec<u8> {
    let mut v = vec![0x0a];
    let mut n = text.len();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            v.push(b);
            break;
        }
        v.push(b | 0x80);
    }
    v.extend_from_slice(text.as_bytes());
    v
}

/// Relay list telling the phone the PC has clipboard data (mirror of its Init).
pub fn clipboard_init_relay(our_id: &str) -> String {
    serde_json::json!([
        {"key": "TaskType", "value": "ACROSS_DEVICE_CLIPBOARD"},
        {"key": "IcdfStatus", "value": "Init"},
        {"key": "RemoteDvd", "value": our_id}
    ])
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capex_response_roundtrip() {
        let agents = super::super::epi::our_agents();
        let r = super::super::epi::capex_response(3, "app.x", "app.x", &agents);
        let got = parse_capex_response(&r);
        assert_eq!(got.len(), agents.len());
        assert_eq!(got[0].1, 4101);
        assert_eq!(got[0].2, "app:clipboardservice");
    }

    #[test]
    fn request_matches_phone_layout() {
        // Same shape as the phone's real request (agents swapped, our sessions).
        let b = service_conn_request(0xb369, 0x1005, &[0x00d4, 0x00b8], &[104, 110]);
        assert_eq!(hex::encode(b), "01b36910056170703a636c6970626f617264736572766963653b000200d400b80068006e050104010000");
    }

    #[test]
    fn clip_proto_long_text() {
        let t = "x".repeat(300);
        let p = clip_data_proto(&t);
        let (d, f, _) = icdf::parse_clip_data(&p);
        assert_eq!((d.len(), f), (300, 0));
    }
}
