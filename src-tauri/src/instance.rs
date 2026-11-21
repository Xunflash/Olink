//! One running copy at a time (the phone ports can only be ours once).
//!
//! The first copy listens on a Unix socket in the private runtime dir
//! (`util::private_dir`, 0700, so only this user can reach it). A later copy
//! connects, says "show" (or "ping" when started hidden, e.g. at login), and
//! exits; the first copy then shows its window. The window process talks to
//! the first copy over the same socket (`ipc`). No D-Bus, no extra threads.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};

pub enum Instance {
    /// We're the only copy; serve this listener (None if it couldn't be made).
    First(Option<UnixListener>),
    /// Another copy is running and has been told.
    Other,
}

pub fn claim(show: bool) -> Instance {
    let Ok(path) = crate::ipc::socket_path() else { return Instance::First(None) };
    if let Ok(mut s) = UnixStream::connect(&path) {
        let _ = s.write_all(if show { b"show\n" } else { b"ping\n" });
        return Instance::Other;
    }
    // Nobody answered: a stale socket from a crash, or none.
    let _ = std::fs::remove_file(&path);
    match UnixListener::bind(&path) {
        Ok(l) => Instance::First(Some(l)),
        Err(e) => {
            tracing::warn!("single-instance socket: {e}");
            Instance::First(None)
        }
    }
}
