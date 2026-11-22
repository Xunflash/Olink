//! A one-line summary of the phone's state for the desktop bar (the Noctalia
//! "island" widget in `integrations/noctalia/`), pushed whenever it changes:
//!
//!   connected  phone  battery  charging  casting  transfer_dir  transfer_name  transfer_pct
//!
//! tab-separated; battery -1 = unknown; transfer_dir "" / "up" / "down".
//! `olink status` prints the current line (see `ipc`).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::events::{Event, TransferState};

#[derive(Clone, Default, PartialEq)]
struct Status {
    connected: bool,
    phone: String,
    battery: i32,
    charging: bool,
    casting: bool,
    dir: &'static str,
    name: String,
    pct: u8,
}

struct State {
    now: Status,
    pushed: Option<Status>,
    last_push: Option<Instant>,
}

static STATE: Mutex<State> = Mutex::new(State {
    now: Status { connected: false, phone: String::new(), battery: -1, charging: false, casting: false, dir: "", name: String::new(), pct: 0 },
    pushed: None,
    last_push: None,
});

/// No tabs or newlines inside a field.
fn field(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(80).collect()
}

fn line(s: &Status) -> String {
    if !s.connected {
        return "0".into();
    }
    format!(
        "1\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        field(&s.phone),
        s.battery,
        s.charging as u8,
        s.casting as u8,
        s.dir,
        field(&s.name),
        s.pct
    )
}

/// The current line, for `olink status`.
pub fn current() -> String {
    line(&STATE.lock().unwrap_or_else(|p| p.into_inner()).now)
}

/// The paired phone's name, from the newest pairing record.
fn phone_name() -> String {
    let dir = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share")))
        .map(|d| d.join("olink"));
    let Some(Ok(rd)) = dir.map(std::fs::read_dir) else { return String::new() };
    rd.flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("pairing-"))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max_by_key(|(t, _)| *t)
        .and_then(|(_, p)| serde_json::from_slice::<serde_json::Value>(&std::fs::read(p).ok()?).ok())
        .and_then(|v| v["peer_name"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Fold an app event into the status; push it to the bar if it changed.
pub fn on_event(ev: &Event) {
    let mut st = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let s = &mut st.now;
    let mut progress_only = false;
    match ev {
        Event::Connected { .. } => {
            s.connected = true;
            s.phone = phone_name();
        }
        Event::Disconnected => *s = Status { battery: -1, ..Default::default() },
        Event::Battery { level, charging } => {
            s.battery = *level as i32;
            s.charging = *charging;
        }
        Event::Casting { on } => s.casting = *on,
        Event::Transfer { outgoing, state, files, bytes, done, .. } => match state {
            TransferState::Sending | TransferState::Receiving | TransferState::Waiting => {
                let pct = if *bytes > 0 { (done * 100 / bytes).min(100) as u8 } else { 0 };
                progress_only = s.dir != "" && s.pct != pct;
                s.dir = if *outgoing { "up" } else { "down" };
                s.name = files.first().cloned().unwrap_or_default();
                s.pct = pct;
            }
            TransferState::Done | TransferState::Failed => {
                s.dir = "";
                s.name.clear();
                s.pct = 0;
            }
        },
        _ => return,
    }
    if st.pushed.as_ref() == Some(&st.now) {
        return;
    }
    // Progress ticks: at most one a second; anything else goes out at once.
    if progress_only && st.last_push.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
        return;
    }
    st.pushed = Some(st.now.clone());
    st.last_push = Some(Instant::now());
    push(line(&st.now));
}

/// Olink is quitting: the bar must stop showing a connected phone. Waits
/// (briefly) so the message goes out before the process ends.
pub fn on_quit() {
    let child = std::process::Command::new("noctalia")
        .args(["msg", "plugin", "whozdgt/olink:island", "all", "status", "0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if let Ok(mut child) = child {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
    }
}

/// Tell the bar widget (if Noctalia is running it): its IPC, no shell.
fn push(line: String) {
    let _ = std::process::Command::new("noctalia")
        .args(["msg", "plugin", "whozdgt/olink:island", "all", "status", &line])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|mut child| std::thread::spawn(move || child.wait()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_format() {
        assert_eq!(line(&Status::default()), "0");
        let s = Status { connected: true, phone: "Find\tX9\nUltra".into(), battery: 82, charging: true, dir: "up", name: "a.mp4".into(), pct: 41, ..Default::default() };
        assert_eq!(line(&s), "1\tFind X9 Ultra\t82\t1\t0\tup\ta.mp4\t41");
    }
}
