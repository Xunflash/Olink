//! Input back to the phone during a cast (OPPO's binary UIBC, as parsed by
//! HeyCast `x2/a.java` MacUibcPolicy — we are classed as SYNERGY_MAC).
//!
//! Sent as binary messages on our WebRTC data channel. Layout (big-endian):
//!
//! ```text
//! [0x81][0][N=0][0][0][eventType]  payload…  [8-byte input time, ms]
//! eventType 0 key:    action u8 (0 down,1 up), keyCode u32 (Android), meta u32, deviceId u32
//! eventType 2 touch:  action u32 (0 down,1 up,2 move), count u8,
//!                     count × (id u32, x u32, y u32, 2 pad), width u16, height u16, deviceId u32
//! eventType 3 scroll: x u32, y u32, width u16, height u16, hscroll i32, vscroll i32, deviceId u32
//! ```
//!
//! The phone's data channel strips the trailing 8 bytes as `inputTime` (it
//! keeps our clock's offset from the first down event). x/y are in `width` ×
//! `height` space (the video frame) and the phone scales to its display.
//! deviceId must be 969..=1008 or it becomes 999; we use 999.

const DEVICE_ID: u32 = 999;

fn header(event_type: u8) -> Vec<u8> {
    vec![0x81, 0, 0, 0, 0, event_type]
}

fn with_time(mut b: Vec<u8>, time_ms: u64) -> Vec<u8> {
    b.extend_from_slice(&time_ms.to_be_bytes());
    b
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchAction {
    Down = 0,
    Up = 1,
    Move = 2,
}

/// One-finger touch at (x, y) in a `w`×`h` frame.
pub fn touch(action: TouchAction, x: u32, y: u32, w: u16, h: u16, time_ms: u64) -> Vec<u8> {
    let mut b = header(2);
    b.extend_from_slice(&(action as u32).to_be_bytes());
    b.push(1);
    b.extend_from_slice(&0u32.to_be_bytes()); // pointer id
    b.extend_from_slice(&x.min(w as u32).to_be_bytes());
    b.extend_from_slice(&y.min(h as u32).to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    b.extend_from_slice(&DEVICE_ID.to_be_bytes());
    with_time(b, time_ms)
}

/// Mouse wheel at (x, y): `v` > 0 scrolls up (Android AXIS_VSCROLL).
pub fn scroll(x: u32, y: u32, w: u16, h: u16, hscroll: i32, vscroll: i32, time_ms: u64) -> Vec<u8> {
    let mut b = header(3);
    b.extend_from_slice(&x.to_be_bytes());
    b.extend_from_slice(&y.to_be_bytes());
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    b.extend_from_slice(&hscroll.to_be_bytes());
    b.extend_from_slice(&vscroll.to_be_bytes());
    b.extend_from_slice(&DEVICE_ID.to_be_bytes());
    with_time(b, time_ms)
}

/// Android key event (`down` = ACTION_DOWN).
pub fn key(down: bool, keycode: u32, meta: u32, time_ms: u64) -> Vec<u8> {
    let mut b = header(0);
    b.push(if down { 0 } else { 1 });
    b.extend_from_slice(&keycode.to_be_bytes());
    b.extend_from_slice(&meta.to_be_bytes());
    b.extend_from_slice(&DEVICE_ID.to_be_bytes());
    with_time(b, time_ms)
}

/// Android meta state for Shift.
pub const META_SHIFT_ON: u32 = 0x1;

/// Map a GStreamer navigation key name (an X keysym name such as "a",
/// "Return", "BackSpace", "Left") to an Android keycode and whether Shift is
/// implied. Escape maps to BACK, Home/Super to HOME.
pub fn android_keycode(name: &str) -> Option<(u32, bool)> {
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        return match c {
            'a'..='z' => Some((29 + (c as u32 - 'a' as u32), false)),
            'A'..='Z' => Some((29 + (c as u32 - 'A' as u32), true)),
            '0'..='9' => Some((7 + (c as u32 - '0' as u32), false)),
            ' ' => Some((62, false)),
            ',' => Some((55, false)),
            '.' => Some((56, false)),
            '/' => Some((76, false)),
            '-' => Some((69, false)),
            '=' => Some((70, false)),
            ';' => Some((74, false)),
            '\'' => Some((75, false)),
            '[' => Some((71, false)),
            ']' => Some((72, false)),
            '\\' => Some((73, false)),
            '`' => Some((68, false)),
            '@' => Some((77, false)),
            _ => None,
        };
    }
    Some(match name {
        "space" => (62, false),
        "Return" | "KP_Enter" => (66, false),
        "BackSpace" => (67, false),
        "Delete" => (112, false),
        "Tab" => (61, false),
        "Escape" => (4, false), // BACK
        "Home" | "Super_L" | "Super_R" => (3, false),
        "Left" => (21, false),
        "Right" => (22, false),
        "Up" => (19, false),
        "Down" => (20, false),
        "Page_Up" => (92, false),
        "Page_Down" => (93, false),
        "End" => (123, false),
        "comma" => (55, false),
        "period" => (56, false),
        "slash" => (76, false),
        "minus" => (69, false),
        "equal" => (70, false),
        "semicolon" => (74, false),
        "apostrophe" => (75, false),
        "bracketleft" => (71, false),
        "bracketright" => (72, false),
        "backslash" => (73, false),
        "grave" => (68, false),
        "at" => (77, false),
        "F1" => (131, false), // spare: unused by Android UI
        "XF86AudioRaiseVolume" => (24, false),
        "XF86AudioLowerVolume" => (25, false),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Re-implement the phone's reads (x2/a.java) to check our layout.
    fn rd(b: &[u8], at: usize, n: usize) -> u64 {
        b[at..at + n].iter().fold(0u64, |a, &x| (a << 8) | x as u64)
    }
    /// Strip the 8-byte input time like PeerConnectionClient.onMessage does.
    fn strip(b: &[u8]) -> (&[u8], u64) {
        let n = b.len() - 8;
        (&b[..n], rd(b, n, 8))
    }

    #[test]
    fn touch_matches_phone_parser() {
        let raw = touch(TouchAction::Move, 540, 1200, 1080, 2376, 12345);
        let (b, t) = strip(&raw);
        assert_eq!(t, 12345);
        assert_eq!(b[0], 0x81);
        let n = b[2] as usize;
        assert_eq!(b[n + 5], 2, "eventType touch");
        let i7 = n + 6;
        assert_eq!(rd(b, i7, 4), 2, "action move");
        assert_eq!(b[i7 + 4], 1, "one pointer");
        let p = i7 + 5;
        assert_eq!(rd(b, p, 4), 0, "pointer id");
        assert_eq!(rd(b, p + 4, 4), 540);
        assert_eq!(rd(b, p + 8, 4), 1200);
        assert_eq!(rd(b, b.len() - 8, 2), 1080, "width");
        assert_eq!(rd(b, b.len() - 6, 2), 2376, "height");
        assert_eq!(rd(b, b.len() - 4, 4), 999, "deviceId");
        assert_eq!(p + 14 + 8, b.len(), "pointer block + trailer");
    }

    #[test]
    fn key_matches_phone_parser() {
        let raw = key(true, 29, META_SHIFT_ON, 1);
        let (b, _) = strip(&raw);
        let i7 = b[2] as usize + 6;
        assert_eq!(b[b[2] as usize + 5], 0, "eventType key");
        assert_eq!(b[i7], 0, "down");
        assert_eq!(rd(b, i7 + 1, 4), 29);
        assert_eq!(rd(b, i7 + 5, 4), 1);
        assert_eq!(rd(b, i7 + 9, 4), 999);
    }

    #[test]
    fn scroll_matches_phone_parser() {
        let raw = scroll(10, 20, 1080, 2376, 0, -1, 1);
        let (b, _) = strip(&raw);
        let i7 = b[2] as usize + 6;
        assert_eq!(b[b[2] as usize + 5], 3, "eventType scroll");
        assert_eq!(rd(b, i7, 4), 10);
        assert_eq!(rd(b, i7 + 4, 4), 20);
        assert_eq!(rd(b, i7 + 8, 2), 1080);
        assert_eq!(rd(b, i7 + 10, 2), 2376);
        assert_eq!(rd(b, i7 + 16, 4) as u32 as i32, -1, "vscroll as Java int");
        assert_eq!(rd(b, i7 + 20, 4), 999);
    }

    #[test]
    fn keymap() {
        assert_eq!(android_keycode("a"), Some((29, false)));
        assert_eq!(android_keycode("Z"), Some((54, true)));
        assert_eq!(android_keycode("5"), Some((12, false)));
        assert_eq!(android_keycode("Return"), Some((66, false)));
        assert_eq!(android_keycode("BackSpace"), Some((67, false)));
        assert_eq!(android_keycode("Escape"), Some((4, false)));
        assert_eq!(android_keycode("Shift_L"), None);
    }
}
