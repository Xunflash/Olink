//! User settings, saved in `$XDG_CONFIG_HOME/olink/settings.json`
//! (default `~/.config/…`). The `OPLUS_*` environment variables still win
//! when set, for testing.
//!
//! Every field is a closed set of values (enums, bool), so the web page can
//! only pick among them: nothing it sends turns into a path, a command or a
//! free-form string.

use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CastQuality {
    /// 720 wide: for a weak Wi-Fi link.
    Smooth,
    /// 1080 wide (default).
    #[default]
    Balanced,
    /// The phone's full 1440 width.
    Sharp,
}

impl CastQuality {
    /// (width, height, fps) to ask the phone for (its screen is 1440×3168).
    pub fn size(self) -> (u32, u32, u32) {
        match self {
            CastQuality::Smooth => (720, 1584, 60),
            CastQuality::Balanced => (1080, 2376, 60),
            CastQuality::Sharp => (1440, 3168, 60),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScrollMode {
    /// Trackpad / wheel scrolling becomes a finger swipe (default).
    #[default]
    Swipe,
    /// Sent as scroll events (some apps ignore them).
    Scroll,
}

/// The window's look (Streamline's two themes).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    /// Midnight when the desktop is dark, Classic when it's light.
    #[default]
    System,
    /// Black and green.
    Midnight,
    /// Light, with the bright accents.
    Classic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    pub cast_quality: CastQuality,
    pub scroll_mode: ScrollMode,
    /// Show phone notifications as desktop pop-ups.
    pub desktop_notifications: bool,
    /// Sync the clipboard both ways. Password-manager copies are never sent
    /// to the phone, whatever this says.
    pub share_clipboard: bool,
    /// Start (in the tray) when the user logs in.
    pub start_on_login: bool,
    pub theme: Theme,
}

impl Default for Settings {
    fn default() -> Self {
        Self { cast_quality: CastQuality::default(), scroll_mode: ScrollMode::default(), desktop_notifications: true, share_clipboard: true, start_on_login: true, theme: Theme::System }
    }
}

fn path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("olink").join("settings.json")
}

static CURRENT: LazyLock<RwLock<Settings>> = LazyLock::new(|| {
    let s = std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    RwLock::new(s)
});

pub fn get() -> Settings {
    *CURRENT.read().unwrap_or_else(|p| p.into_inner())
}

/// Replace the settings and save them (write a temp file, then rename).
pub fn set(s: Settings) -> anyhow::Result<()> {
    *CURRENT.write().unwrap_or_else(|p| p.into_inner()) = s;
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&s)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_take_defaults_and_unknown_values_fail() {
        let s: Settings = serde_json::from_str(r#"{"scroll_mode":"scroll"}"#).unwrap();
        assert_eq!(s, Settings { scroll_mode: ScrollMode::Scroll, ..Settings::default() });
        assert!(serde_json::from_str::<Settings>(r#"{"cast_quality":"/etc/passwd"}"#).is_err());
    }
}
