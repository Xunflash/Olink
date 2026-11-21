# Architecture

Olink plays the part of the Windows PC that a ColorOS phone already knows how
to talk to. The phone connects to it over Wi-Fi exactly as it would to OPPO's
own PC app; nothing of OPPO's runs on the Linux side, and no account or cloud
is involved.

This page is the map: what runs, in what order, and where it lives in the code.
The wire formats themselves are specified in [SCP.md](SCP.md) (pairing and the
secure channel), [PROTOCOL.md](PROTOCOL.md) (file transfer) and
[CAST.md](CAST.md) (the phone screen).

## How a connection comes up

```text
  phone                                      Olink
  ─────                                      ─────
  scans the QR  ◀───────────────────────────  QR carries this PC's address,
                                              nothing secret
  TCP 10152  ──────────────────────────────▶  SCP server: HELLO, SYNC,
                                              UKey2, SYNC_SECURE
                                              → session key (KSC) from the phone
                                              "Allow this phone?" ── no ─▶ dropped
                                                     │ yes
                                              key saved; phone remembered
  "interact hello" ─────────────────────────▶  "accept"
                    ◀─── TCP probe ──────────  connect back to phone:10153
  TCP 46888 (data channel) ─────────────────▶  peer descriptor exchange,
                                              KSC proof, capability exchange
                                              → connected
  services over the data channel  ◀────────▶  clipboard, files, notifications,
                                              battery, the phone screen
```

1. **Pairing QR** — `discovery::qr_probe` builds the same `oconn` QR the
   Windows app shows: this PC's address and identity, no secret.
2. **SCP** — the phone opens TCP **10152** and runs OPPO's secure channel
   protocol; `scp::server` is the server side, `scp::ukey2` the key exchange
   (stock Google UKey2, cipher P256_SHA512, plus one OPPO addition). Every
   packet after that is AES-256-GCM. See SCP.md and CRYPTO.md.
3. **Your OK** — the QR has no secret, so anyone on the network could run that
   handshake. `approval` asks you before a new phone may pair; only **Allow**
   saves its key. Requests are rate-limited and one at a time.
4. **Data channel** — the phone opens TCP **46888**; `scp::epi` exchanges peer
   descriptors and proves both sides hold the key, then capability exchange
   finishes the connection.
5. **Services** run as sessions over that channel (`scp::icdf`), with
   `scp::dbr` carrying publish/subscribe messages (battery, notifications,
   cast requests).

A phone that has paired before skips steps 1–3: it reconnects with its saved
key.

## What each feature uses

| Feature | Modules | Notes |
|---|---|---|
| Clipboard, phone → PC | `scp::icdf` | Service session on the data channel. |
| Clipboard, PC → phone | `scp::pcclip` | Watches `wl-paste` (or `xclip`); password-manager copies are skipped. |
| Files, phone → PC | `scp::oshare`, `protocol` | The phone's OPPO Share server; mutual TLS with the cert it sends. Saved to `~/Downloads/Olink`. |
| Files, PC → phone | `scp::pcsend`, `protocol` | Olink runs a TLS WebSocket + HTTPS server on **46890**; the phone pulls. |
| Notifications, battery | `scp::dbr` (via `discovery::qr_probe`) | DataBus topics; Olink asks the phone to forward notifications. |
| Phone screen | `scp::odmf`, `scp::castrx`, `scp::uibc` | ODMF signalling on **46892**, WebRTC video into a GStreamer window, input sent back as UIBC. Media on UDP **46900–46999**. |
| Single-app cast picker | `scp::phoneapps` | The phone's own list of castable apps, names and icons. |

## Two processes

The app keeps its footprint small by splitting itself:

- **Background process** — started at login (`--hidden`) or when you open
  Olink. Holds the phone connection, the tray icon (`desktop`), the cast
  window and the settings. About 35 MB while idle.
- **Window process** (`--window`) — the Tauri web view, started when you open
  the window and gone when you close it, so its memory only counts while it's
  on screen. `commands` are the page's Tauri commands; most are forwarded to
  the background process.

They talk over a Unix socket in a private (0700) runtime directory
(`ipc`, `instance`). The same socket keeps a second copy from starting:
opening Olink again just shows the existing window. `events` carries what the
phone reports (connected, battery, transfers, notifications) to the page.

## Code map

```text
src/                        the window's page (plain HTML/CSS/JS, no build step; see UI.md)
  index.html  main.js  styles.css  assets/
src-tauri/src/
  main.rs                   entry point: tray app, --window, --hidden, the CLIs below
  discovery/qr_probe.rs     the pairing QR and the phone connection (runs everything after it)
  scp/                      OPPO's protocols
    mod.rs  server.rs         SCP framing and server state machine
    ukey2.rs                  UKey2 P256_SHA512 + OPPO's ivSpec
    epi.rs                    data channel: peer descriptors, KSC proof
    icdf.rs  dbr.rs           service sessions; DataBus publish/subscribe
    pcclip.rs                 PC → phone clipboard
    oshare.rs  pcsend.rs      files, phone → PC and PC → phone
    odmf.rs  castrx.rs  uibc.rs  phoneapps.rs   the phone screen
  protocol/                 OPPO Share message types and TLS (from the Windows SDK)
  approval.rs               "Allow this phone?"
  desktop.rs  ipc.rs  instance.rs  events.rs  commands.rs   the app around it
  settings.rs  autostart.rs  util.rs
  ble/                      Bluetooth research probe (not used to connect)
```

## Ports

Everything is inbound from the phone except the probe to its port 10153.

| Port | Protocol | Use |
|---|---|---|
| 10150 | TCP | The phone's discovery probe |
| 10151 | TCP | Advertised data-service port |
| 10152 | TCP | SCP: pairing and the secure channel |
| 46888 | TCP + UDP | The data channel |
| 46890 | TCP | Files, PC → phone |
| 46892 | TCP | Phone-screen signalling |
| 46900–46999 | UDP | Phone-screen media (WebRTC) |

The package installs a ufw profile with these: `sudo ufw allow Olink`.

## Where things are kept

| What | Where |
|---|---|
| Paired phones (their keys) | `~/.local/share/olink/pairing-<phone>.json` |
| Settings | `$XDG_CONFIG_HOME/olink/settings.json` (usually `~/.config/olink/`) |
| Received files | `~/Downloads/Olink` |
| Runtime files (socket, QR) | `$XDG_RUNTIME_DIR/olink/`, private to you |

## Diagnostic tools

The same binary has two command-line tools, used while working out the
protocol and still handy for debugging:

```bash
olink net-probe pair [ip]   # run the phone server in a terminal, with logs
olink net-probe qr [ip]     # show the QR and only log what the phone sends
olink ble-probe scan        # list nearby Bluetooth LE advertisers
```

Set `OPLUS_DEBUG=1` for raw protocol dumps.
