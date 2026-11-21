# Olink

**Your OPPO, OnePlus or realme phone on Linux.** Olink speaks the phone's own
PC-connection protocol ("O+ Connect" / Device connect → PC in ColorOS), so the
phone connects **directly to Linux** over Wi-Fi: no OPPO PC app, no cloud, no
account.

Built and tested with ColorOS 16 (OPPO Find X9 Ultra) on Arch / CachyOS with
Hyprland.

- Pair by scanning a QR code, then allow the phone on the PC; afterwards the
  phone reconnects by itself.
- Clipboard both ways (password-manager copies are never sent).
- Files and folders both ways: **Send files…**, **Send folder…**, drag and
  drop, or share to the PC from the phone.
- Phone notifications as desktop pop-ups, battery level.
- The phone screen in a window you control with mouse, trackpad and keyboard,
  or just one app while the phone stays free to use.
- Runs in the tray and starts with your login, using ~35 MB in the
  background: the window (a web view) only exists while it's open.

## Install

### Arch / CachyOS

```bash
git clone https://github.com/whozdgt/Olink && cd Olink/packaging/arch
makepkg -si
```

Uninstall with `sudo pacman -R olink`.

### AppImage (any distribution)

```bash
npm install
NO_STRIP=true GSTREAMER_INCLUDE_BAD_PLUGINS=1 npm run tauri build -- --bundles appimage
# → src-tauri/target/release/bundle/appimage/  (needs patchelf)
```

Runtime needs: WebKitGTK 4.1, GTK 3, libayatana-appindicator, GStreamer with
the good/bad plugins, libnice and gst-libav (phone screen), wl-clipboard,
libnotify, xdg-desktop-portal.

### Firewall

The phone connects in to TCP 10150-10152, 46888, 46890 and 46892, and the
phone screen uses UDP 46900-46999. With ufw (the package installs a profile):

```bash
sudo ufw allow Olink
```

## Using it

Open **Olink**, then on the phone go to **Settings → Device connect → PC**
and scan the QR code. Olink asks whether to allow the phone; only allow it if
you just scanned the code.

Closing the window keeps Olink in the tray (the phone stays connected);
**Quit** in the tray menu ends it. Settings (⚙): screen quality, swipe or
scroll for the touchpad, notifications, clipboard sharing, start on login.

## Security

The QR code carries no secret, so pairing always needs your OK on the PC.
After that the link uses the phone's own encryption (UKey2 pairing, AES-GCM),
replays are refused, and nothing the phone sends is ever run or shown as
HTML. See the security notes in [PROGRESS.md](PROGRESS.md) for what was
reviewed, what was fixed and the protocol's own limits.

## Development

```bash
npm install
npm run tauri dev                  # run from source
cd src-tauri && cargo test         # unit tests
cargo test -- --ignored live_      # rogue-pairing test against the running app
OPLUS_DEBUG=1 npm run tauri dev    # also log raw protocol dumps
```

`olink net-probe pair` runs the phone server in a terminal (the QR is written
to `$XDG_RUNTIME_DIR/olink/pairing-qr.svg`). UI work: see [UI.md](UI.md).

## Docs

- **[PROGRESS.md](PROGRESS.md)**: what works, how, the security review.
- **[CAST.md](CAST.md)**: the phone screen (ODMF signalling, WebRTC, UIBC input).
- **[SCP.md](SCP.md)**, **[PAIRING.md](PAIRING.md)**, **[CRYPTO.md](CRYPTO.md)**: pairing and its crypto.
- **[PROTOCOL.md](PROTOCOL.md)**: file transfer.
- **[UI.md](UI.md)**: the window's page, commands and events.

## Licence

MIT, see [LICENSE](LICENSE).

## Legal

Reverse-engineering for interoperability is broadly permitted (EU Software
Directive; UK CDPA s.50B; US DMCA §1201(f)). This is a clean-room re-implementation
from observed behaviour and public standards. Do not redistribute OPPO's binaries,
code, bundled certificate, or trademarks/assets. `google/ukey2` and SecureMessage
are Apache-2.0 — include their license when linking. Not legal advice.

OPPO, OnePlus, realme, ColorOS and O+ Connect are trademarks of their owners.
Olink is an independent project and isn't affiliated with or endorsed by them.
