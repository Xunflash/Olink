//! The phone's full list of apps that can be cast on their own, with names
//! and icons.
//!
//! Publishing `{"key":"MacClientVersion",…}` on `Oplus_MacConnect` makes the
//! phone (linker `MacDbsReceiver` → scene type 57 → `OcastSdkWrapper.
//! initHttpAndAppInfo`) start a small plain-HTTP server (`HttpServer`, ports
//! 8080/8111/8222/8333/8444) and publish `{"key":"http_msg","value":
//! "{\"ip\":…,\"port\":…}"}`. `GET /data/all_white_app` there answers
//! `ResultData{code, message, data}` where `data` is a JSON string
//! `{"all_white_app": {pkg: {name, name64, icon}}}`: the installed apps on the
//! single-app-cast ("mirage") allow-list, icons as base64 WebP.
//!
//! Everything here comes from the network, so it's checked: we only ever
//! connect to the connected phone's own address (the message's `ip` is
//! ignored), the response is bounded in size and time, package names must
//! look like Android package names, labels lose control characters, and an
//! icon is kept only if its bytes really are WebP/PNG/JPEG (re-encoded by us).

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Whole response: ~100 apps × a few KB of icon each, with lots of room.
const MAX_BODY: usize = 32 * 1024 * 1024;
const MAX_ICON: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    pub pkg: String,
    pub name: String,
    /// `data:image/…;base64,…`, or empty.
    pub icon: String,
}

/// The DataBus publish that makes the phone start its app-list server.
pub fn client_version_payload() -> String {
    serde_json::json!({"key": "MacClientVersion", "value": "3.1.0"}).to_string()
}

/// `http_msg` (Oplus_MacConnect) → the phone's app-list server port.
pub fn parse_http_msg(payload: &str) -> Option<u16> {
    let outer: serde_json::Value = serde_json::from_str(payload).ok()?;
    let msg: serde_json::Value = serde_json::from_str(outer["dbs_msg_payload"].as_str()?).ok()?;
    if msg["key"] != "http_msg" {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(msg["value"].as_str()?).ok()?;
    let port = v["port"].as_u64()?;
    (1..=65535).contains(&port).then_some(port as u16)
}

/// A real Android package name: `[A-Za-z0-9_]` segments joined by dots.
pub fn valid_package(pkg: &str) -> bool {
    pkg.len() <= 255
        && pkg.contains('.')
        && pkg.split('.').all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Fetch the full app list from the phone at `phone:port`.
pub async fn fetch_all_apps(phone: IpAddr, port: u16) -> anyhow::Result<Vec<AppInfo>> {
    let body = tokio::time::timeout(Duration::from_secs(20), http_get(phone, port, "/data/all_white_app")).await
        .map_err(|_| anyhow::anyhow!("app list: timed out"))??;
    parse_all_apps(&body)
}

/// Minimal HTTP/1.1 GET for the phone's server (it answers `Connection:
/// close` with no Content-Length, so the body runs to EOF).
async fn http_get(ip: IpAddr, port: u16, path: &str) -> anyhow::Result<Vec<u8>> {
    let mut s = tokio::net::TcpStream::connect((ip, port)).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_BODY {
            anyhow::bail!("app list: response too large");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow::anyhow!("app list: no HTTP head"))?;
    let head = String::from_utf8_lossy(&buf[..split]);
    let status = head.split_whitespace().nth(1).unwrap_or("");
    anyhow::ensure!(status == "200", "app list: HTTP {status}");
    Ok(buf[split + 4..].to_vec())
}

fn parse_all_apps(body: &[u8]) -> anyhow::Result<Vec<AppInfo>> {
    let result: serde_json::Value = serde_json::from_slice(body)?;
    let data: serde_json::Value = serde_json::from_str(result["data"].as_str().unwrap_or("{}"))?;
    let map = data["all_white_app"].as_object().ok_or_else(|| anyhow::anyhow!("app list: no all_white_app"))?;
    let mut apps: Vec<AppInfo> = map
        .iter()
        .filter(|(pkg, _)| valid_package(pkg))
        .map(|(pkg, info)| {
            let mut name = clean_label(info["name"].as_str().unwrap_or(""));
            if name.is_empty() {
                // name64: base64 of the label.
                name = info["name64"]
                    .as_str()
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    .map(|b| clean_label(&String::from_utf8_lossy(&b)))
                    .unwrap_or_default();
            }
            let icon = info["icon"].as_str().and_then(icon_data_url).unwrap_or_default();
            AppInfo { pkg: pkg.clone(), name, icon }
        })
        .collect();
    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.pkg.cmp(&b.pkg)));
    Ok(apps)
}

/// A label for display: no control characters, at most 80 characters.
fn clean_label(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect::<String>().trim().to_string()
}

/// base64 icon from the phone → a data URL, only for real WebP/PNG/JPEG bytes.
fn icon_data_url(b64: &str) -> Option<String> {
    let b64: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if b64.len() > MAX_ICON * 4 / 3 + 4 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let mime = if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else {
        return None;
    };
    Some(format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_msg_gives_port() {
        let inner = serde_json::json!({"key": "http_msg", "value": "{\"ip\":\"10.0.0.2\",\"port\":8111}"}).to_string();
        let outer = serde_json::json!({"dbs_msg_payload": inner}).to_string();
        assert_eq!(parse_http_msg(&outer), Some(8111));
        let other = serde_json::json!({"dbs_msg_payload": "{\"key\":\"batteryInfo\",\"value\":\"{}\"}"}).to_string();
        assert_eq!(parse_http_msg(&other), None);
    }

    #[test]
    fn package_names() {
        assert!(valid_package("com.instagram.android"));
        assert!(valid_package("org.mozilla.firefox_beta"));
        assert!(!valid_package("noDots"));
        assert!(!valid_package("com..x"));
        assert!(!valid_package("com.x\"><img"));
        assert!(!valid_package("com.x/../y"));
    }

    #[test]
    fn app_list_is_checked() {
        let webp = base64::engine::general_purpose::STANDARD.encode(b"RIFF\x10\0\0\0WEBPVP8 tail");
        let html = base64::engine::general_purpose::STANDARD.encode(b"<svg onload=alert(1)>");
        let name64 = base64::engine::general_purpose::STANDARD.encode("Café".as_bytes());
        let data = serde_json::json!({"all_white_app": {
            "com.b.app": {"name": "Beta\u{7}", "icon": webp},
            "com.a.app": {"name": "", "name64": name64, "icon": html},
            "bad pkg": {"name": "x"},
        }})
        .to_string();
        let body = serde_json::json!({"code": 200, "message": "Success", "data": data}).to_string();
        let apps = parse_all_apps(body.as_bytes()).unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0], AppInfo { pkg: "com.b.app".into(), name: "Beta".into(), icon: format!("data:image/webp;base64,{webp}") });
        assert_eq!(apps[1].name, "Café");
        assert_eq!(apps[1].icon, ""); // not an image: dropped
    }
}
