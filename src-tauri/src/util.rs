//! Small shared helpers: safe console output, the debug switch, and a
//! private directory for runtime files.

use std::path::PathBuf;

/// `OPLUS_DEBUG=1`: also print raw protocol dumps (message bodies, hex,
/// notification and clipboard text). Off by default, because the log of an
/// installed app ends up in the system journal.
pub fn debug() -> bool {
    static ON: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| std::env::var("OPLUS_DEBUG").is_ok_and(|v| !v.is_empty() && v != "0"));
    *ON
}

/// Bidi overrides and zero-width characters: they make text display
/// differently from what it is.
pub fn is_invisible_format(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}

/// Text for the terminal: control characters (ESC included, so no ANSI/OSC
/// sequences from phone-supplied text) and bidi tricks are shown escaped.
/// Newlines and tabs are kept.
pub fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\n' || c == '\t' {
            out.push(c);
        } else if c.is_control() || is_invisible_format(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// Where `println!` goes (see the macro in main.rs). Write errors (a closed
/// stdout) are ignored instead of panicking like std's println!.
pub fn print_line(s: String) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", clean(&s));
}

/// A directory only this user can read, for runtime files (the QR image,
/// debug logs): `$XDG_RUNTIME_DIR/olink`, else
/// `~/.cache/olink`. Never the shared /tmp, where another
/// account could plant symlinks or read what we write.
pub fn private_dir() -> anyhow::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| anyhow::anyhow!("no XDG_RUNTIME_DIR or HOME"))?;
    let dir = base.join("olink");
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let meta = std::fs::symlink_metadata(&dir)?;
    anyhow::ensure!(meta.is_dir(), "{} is not a directory", dir.display());
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// The app used to be called "oplus-connect-linux": move its settings and
/// pairing keys to the new name once, and drop the old login entry (the
/// new one is written from the start-on-login setting).
pub fn migrate_old_name() {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let base = |var: &str, fallback: &str| {
        std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).or_else(|| home.as_ref().map(|h| h.join(fallback)))
    };
    for root in [base("XDG_CONFIG_HOME", ".config"), base("XDG_DATA_HOME", ".local/share")].into_iter().flatten() {
        let (old, new) = (root.join("oplus-connect-linux"), root.join("olink"));
        if old.is_dir() && !new.exists() {
            match std::fs::rename(&old, &new) {
                Ok(()) => println!("moved {} to {}", old.display(), new.display()),
                Err(e) => println!("  ! couldn't move {}: {e}", old.display()),
            }
        }
    }
    if let Some(cfg) = base("XDG_CONFIG_HOME", ".config") {
        let _ = std::fs::remove_file(cfg.join("autostart").join("oplus-connect-linux.desktop"));
    }
}

/// Fewer malloc arenas: glibc otherwise keeps one per thread that ever
/// allocated (up to 8 × cores), each holding on to freed memory.
pub fn tune_allocator() {
    // SAFETY: plain libc call with a valid option; safe at any time.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 2);
    }
}

/// Hand freed heap memory back to the system (after the window closes or a
/// cast ends, both of which free a lot at once).
pub fn release_memory() {
    // SAFETY: plain libc call; only trims free memory.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// A desktop notification (`notify-send`, if installed), unless turned off
/// with the desktop-notifications setting (or OPLUS_NOTIFY=0). The body is
/// escaped: servers render it as markup, and phone text is untrusted.
pub fn desktop_notify(summary: &str, body: &str) {
    let on = match std::env::var("OPLUS_NOTIFY") {
        Ok(v) => v != "0",
        Err(_) => crate::settings::get().desktop_notifications,
    };
    if !on {
        return;
    }
    let body = body.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    // Arguments go straight to the program (no shell).
    let _ = std::process::Command::new("notify-send")
        .args(["--app-name=Olink", "--icon=olink", "--", summary, &body])
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
    fn escapes_terminal_sequences() {
        let s = clean("hi\x1b]52;c;ZXZpbA==\x07 \u{202e}txt.exe\nnext");
        assert!(!s.contains('\x1b') && !s.contains('\x07') && !s.contains('\u{202e}'));
        assert!(s.contains("\\u{1b}") && s.ends_with("\nnext"));
    }
}
