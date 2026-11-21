//! "Start on login": an XDG autostart entry (`~/.config/autostart`), which
//! systemd/uwsm sessions, Plasma and GNOME all honour. It starts the app with
//! `--hidden` (tray only, no window, so it stays small until it's needed).

use std::path::PathBuf;

const FILE: &str = "olink.desktop";

fn autostart_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|c| c.join("autostart"))
}

/// The program to start: the AppImage itself when running from one, else
/// this executable (e.g. /usr/bin/olink).
fn program() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_absolute()).or_else(|| std::env::current_exe().ok())
}

/// A desktop-entry Exec argument, quoted per the spec.
fn quote(arg: &str) -> String {
    let mut s = String::from("\"");
    for c in arg.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('"');
    s
}

/// Running from a cargo build folder (not installed).
fn in_build_tree(exe: &std::path::Path) -> bool {
    exe.components().any(|c| c.as_os_str() == "target")
}

/// Make the autostart entry match the setting. Only installed copies (the
/// package, an AppImage) register themselves, never a build-folder binary.
pub fn sync(enabled: bool) -> anyhow::Result<()> {
    if cfg!(debug_assertions) || program().is_none_or(|p| std::env::var_os("APPIMAGE").is_none() && in_build_tree(&p)) {
        return Ok(());
    }
    let dir = autostart_dir().ok_or_else(|| anyhow::anyhow!("no config directory"))?;
    let path = dir.join(FILE);
    if !enabled {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => return Ok(()),
        }
    }
    let exe = program().ok_or_else(|| anyhow::anyhow!("can't find this program's path"))?;
    let exe = exe.to_str().ok_or_else(|| anyhow::anyhow!("program path isn't UTF-8"))?;
    anyhow::ensure!(!exe.contains('\n'), "program path contains a newline");
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Olink\nComment=Keeps your phone connected in the background\nExec={} --hidden\nIcon=olink\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        quote(exe)
    );
    std::fs::create_dir_all(&dir)?;
    if std::fs::read_to_string(&path).ok().as_deref() == Some(entry.as_str()) {
        return Ok(());
    }
    let tmp = dir.join(format!(".{FILE}.tmp"));
    std::fs::write(&tmp, entry)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_tree_detection() {
        assert!(in_build_tree(std::path::Path::new("/home/u/proj/src-tauri/target/release/olink")));
        assert!(!in_build_tree(std::path::Path::new("/usr/bin/olink")));
    }

    #[test]
    fn exec_quoting() {
        assert_eq!(quote("/opt/O+ Connect/app"), "\"/opt/O+ Connect/app\"");
        assert_eq!(quote("/a/$x\"y"), "\"/a/\\$x\\\"y\"");
    }
}
