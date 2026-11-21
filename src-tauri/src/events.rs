//! What the phone connection reports to the app window.
//!
//! The connection code (`discovery::qr_probe`, `scp::castrx`) calls `emit`;
//! the Tauri app installs a sink that forwards each event to the web UI. The
//! CLI (`net-probe pair`) installs none, so events cost nothing there.

use std::sync::{Mutex, OnceLock};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Pairing QR is ready (SVG markup) for this address.
    Qr { svg: String, addr: String },
    /// The phone scanned the QR / reconnected and its data channel is up.
    Connected { peer: String },
    /// The phone's data channel closed.
    Disconnected,
    /// Phone battery (`batteryInfo` on `Oplus_MacConnect`).
    Battery { level: u8, charging: bool },
    /// Cast window opened / closed.
    Casting { on: bool },
    /// A notification posted on the phone (System UI notification sync).
    Notification { app: String, title: String, text: String },
    /// Phone apps that can be cast on their own: recent apps (`all_recent_app`)
    /// first, then the phone's full list (`all_white_app`), or apps that
    /// posted notifications until that list arrives.
    Apps { apps: Vec<PhoneApp> },
    /// A file transfer to the phone (`outgoing`) or from it. `bytes` is the
    /// total size, `done` how much has moved so far.
    Transfer { id: String, outgoing: bool, state: TransferState, files: Vec<String>, bytes: u64, done: u64 },
    /// Something the user should see (worded for them), e.g. a dropped folder.
    Error { msg: String },
    /// The phone server isn't running (e.g. another copy holds the ports).
    /// Kept as state, so a window that opens later still shows it.
    Fatal { msg: String },
    /// A phone finished the pairing handshake: may it pair? Answer with the
    /// `answer_pairing` command within `approval::ANSWER_WITHIN`.
    PairRequest { id: String, name: String, model: String, addr: String },
    /// That question is over (answered or timed out).
    PairRequestDone { id: String, allowed: bool },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    /// Queued; waiting for the phone to accept.
    Waiting,
    Sending,
    Receiving,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PhoneApp {
    pub pkg: String,
    /// The app's label, or empty when the phone hasn't told us.
    pub name: String,
    /// `data:image/…` icon checked by us, or empty.
    pub icon: String,
    /// One of the phone's recent apps.
    pub recent: bool,
}

type Sink = Box<dyn Fn(Event) + Send + Sync>;

static SINK: OnceLock<Sink> = OnceLock::new();
/// Last value of each kind, so a window opened later can catch up.
static LAST: Mutex<Vec<Event>> = Mutex::new(Vec::new());

/// Install the receiver of all events (once, at app start).
pub fn set_sink(f: impl Fn(Event) + Send + Sync + 'static) {
    let _ = SINK.set(Box::new(f));
}

pub fn emit(ev: Event) {
    {
        let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
        let same = |e: &Event| std::mem::discriminant(e) == std::mem::discriminant(&ev);
        // Connected/Disconnected replace each other; notifications,
        // transfers, errors and pairing questions are happenings, not state.
        if !matches!(
            ev,
            Event::Notification { .. } | Event::Transfer { .. } | Event::Error { .. } | Event::PairRequest { .. } | Event::PairRequestDone { .. }
        ) {
            last.retain(|e| !same(e) && !(matches!(ev, Event::Connected { .. } | Event::Disconnected) && matches!(e, Event::Connected { .. } | Event::Disconnected)));
            last.push(ev.clone());
        }
    }
    if let Some(f) = SINK.get() {
        f(ev);
    }
}

/// Whether an app window receives events (else we're the CLI).
pub fn has_sink() -> bool {
    SINK.get().is_some()
}

/// Whether a phone's data channel is up right now.
pub fn connected() -> bool {
    LAST.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|e| matches!(e, Event::Connected { .. }))
}

/// The current state (latest QR, connection, battery, casting).
pub fn snapshot() -> Vec<Event> {
    LAST.lock().unwrap_or_else(|p| p.into_inner()).clone()
}
