# Progress & resume point

_Last updated 2026-11-21._

## Where we are

_Updated 2026-11-19 evening: **first successful connection.** The phone shows
"connected" to the Linux PC._

| Step | State |
|---|---|
| 0. Dev environment | **Done**: Rust 1.100, Node 26, webkit2gtk-4.1, bluez tools, android-tools, jadx installed. |
| 1. Protocol smoke test | **Done**: `cargo test` green. |
| 2/3. BLE + GATT layout | **Superseded**: QR first contact is Wi-Fi, not BLE. See PAIRING.md. |
| 4. Pairing + connect | **Works on the real phone.** See "The full connect sequence" below. |
| 5. Clipboard phone → PC | **Works** (2026-11-19). Long text too. See "Clipboard" below. |
| 5b. Clipboard PC → phone | **Works** (2026-11-19). `scp/pcclip.rs`. |
| 6. File sharing (OPPO Share) | **Works both ways** (2026-11-20). See "Files (OPPO Share)" below. |
| 7. Screen casting | **Works** (2026-11-20, `OPLUS_CAST=1`), smooth after tuning; **phone control from the PC works** (tap/drag/keys/swipes). Whole screen or one app. See CAST.md. UDP 46900-46999 must be open. |
| 8. Tauri app | **Works** (2026-11-21): server inside the app, battery, notifications, cast + full app picker (names/icons), Send files… / drag and drop with progress, received files listed, settings dialog. |

## The full connect sequence (all in `net-probe pair`)

1. Phone scans QR → TCP **10152** "SCP": HELLO, SYNC, UKey2, SYNC_SECURE
   (`scp/server.rs`, spec in SCP.md). Gives us the 16-byte **KSC** + alias,
   saved to `~/.local/share/olink/pairing-<peer>.json`.
2. INTERACT: phone sends raw encrypted `"interact hello"`; we reply raw
   `"accept"` (structType 1). Anything else = "rejected by server" (2517).
3. Backward probe: we TCP-connect to **phone:10153** within ~2 s (no data).
   Missing this = "wlan connect failed" → P2P fallback → the phone's generic
   "make sure phone and PC are on the same Wi-Fi" error.
4. Phone opens the data channel to the QR `addr` (**TCP 46888**). Framing
   `[u16 BE len][payload]` (CRC off because we send CLMode 0). **We speak
   first** (`scp/epi.rs`):
   - PD/EPI **OFFER** (type 1) → phone **ANSWER** (type 2).
   - KSC auth: phone 0x10 REQUEST → our 0x11 RESPONSE → phone 0x12 CONFIRM.
     MAC = HMAC-SHA512(KSC, …)[..8], times little-endian inside the MAC.
   - Session frames: `[len][2-byte hdr: 10-bit session id][body]`.
     **CapEx** on session 2: we send sync query `01 03 00000000 00`, the phone
     answers type 2, sends its own query, and we answer type 2 (empty for now).
     Then the phone sends CapEx confirm (type 4) → **connected**.
5. Still undecoded: a 272-byte message on **session 8** right after CapEx,
   and later CapEx queries listing services (e.g.
   `com.oplus.pantaconnect.globaldevice.discovery`). The phone's own service
   list (61 IDs: `system:filetransfer`, `app:clipboardservice`,
   `app:oshare.win.agent`, `tap_share`, …) arrives as a CapEx query body.

The connection only lives while `net-probe pair` runs (the 46888 reader
closes after 120 s with no traffic).

## Clipboard (phone → PC), working

After connect, on the 46888 data channel:
- **SDP probe** (TCP 10150 `QUERY * HTTP/1.1`): reply `ANNOUNCE` (copied from the
  phone's own probe server). The phone then lists the PC as "online".
- **DataBus** = reserved session 8, DataBus header (`04` + u16 id) and the
  per-session **AppCipher**: AES-128-GCM, key/nonce/AAD from
  HMAC-SHA512(KSC, qc‖qs‖t). Router messages (`scp/dbr.rs`): answer the
  phone's HELLO (type 3) with ours, then send `msg_topic_sync` (types 82 + 42)
  subscribing to `Oplus_PcConnect` etc.
- **CapEx record** advertises `app:clipboardservice` (agent 4101, role 0).
  App name must NOT be `com.oplus.linker` (the phone drops its own package).
- **Service connection** (session 1): phone sends type-1 request (agents,
  session ids for channels 104/110); we answer type 2 status 0.
- **Service data sessions**: body = u16 tlSeq ‖ flags(04) ‖ AppCipher(...).
  ACK every tlSeq (`ctrl` header + `01` + seq) or the phone retransmits.
- **ICDF** (`scp/icdf.rs`), OPPO's gRPC framing: config(15), head(7),
  data(8), half-close(9); we answer data(2) empty Result + close(3).
- **Handshake**: when you copy, the phone publishes `IcdfStatus=Init` on
  `Oplus_PcConnect`; we publish the relay list
  `[TaskType=ACROSS_DEVICE_CLIPBOARD, IcdfStatus=Ready, RemoteDvd=<us>]` on
  `Oplus_HeySynergy_PadConnect_CastMaterial`; the phone then calls
  `ClipBoardService/copyToClip` with `ClipData{data=<text>}` → `wl-copy`.

PC → phone is the mirror image (`scp/pcclip.rs`): `wl-paste` watcher →
publish relay `IcdfStatus=Init` on CastMaterial → phone answers
`IcdfStatus=Ready` on `Oplus_PcConnect` → CapEx query finds the phone's
clipboard *provider* agent (its consumer is the one that connected to us) →
our service connection request (session 1) → on the new 104 session we are
the ICDF client: config(15), head(7), data(8, ClipData), half-close(9).

Also seen on the DataBus (not handled yet): battery/screen status
(module 15001), notification sync (`HeySynergy_Notification_*` on
`..._SyncNotification_Publisher`), `QueryPcVersion` on `Oplus_PcConnect`.

Second decompile (clipboard lives in another app): `~/oplus-connect-research/linker/`
(com.oplus.linker, pulled from the phone).

## Files (OPPO Share), working both ways

Runs over the phone's `app:oshare.win.agent` provider (CapEx finds it; we open
a service connection and answer agent-authenticate type 5 with no-cert/trusted).
Win-channel messages are JSON. **Phone → PC they arrive gzipped; PC → phone they
must be plain UTF-8 JSON** (`PtcDataSocket.onReceive` = `new String(bytes)`).

- **Phone → PC** (`scp/oshare.rs`): `init.connected` gives a client cert/key + CA;
  `websocket.request {method: serverstart}` gives the phone's share server.
  Connect `wss://phone:port/websocket` with mTLS, negotiate version, ack the
  `sendRequest` (or fetch `/bigmessage`), `GET /download` each file (a stored
  zip with `{"fileId":…}` in the extra field), send `status`. Files land in
  `~/Downloads/Olink/`. The phone's share server uses a throwaway
  self-signed `CN=localhost` cert (regenerated per server start); `caCert`
  signs only *client* certs, so the server can't be verified. We connect only
  to the phone's own IP and pin the cert for the whole transfer.
- **PC → phone** (`scp/pcsend.rs`): in the app, **Send files…** (GTK native
  chooser through the portal) or drop files on the window (`WindowEvent::DragDrop`
  in Rust; the page never hands us paths). Or drop files into `~/Downloads/Olink/Send/`.
  The server starts once per process; each phone connection swaps in its IP +
  announce channel (it used to re-bind per connection → random port after a
  reconnect). Tasks are announced/offered FIFO; the zip is streamed (CRC pass,
  then data), files ≥ 4 GiB refused (no zip64). `Event::Transfer` reports
  waiting/sending/done/failed with progress; app-picked files are never moved.
  PC runs a self-signed TLS WS+HTTPS server on **46890** (open it in ufw),
  sends `websocket.request {method: serverstart, ip, port}` (plain JSON!), the
  phone connects to `/websocket`, we send `action sendRequest` with the full
  offer **plus `messageId`**. The phone (file-manager version ≥ 3, `ja.d`)
  ignores the inline offer and `GET /bigmessage?taskId&messageId`, which must
  return the offer JSON. Then it acks, shows the accept card, `GET /download`s,
  sends `status type 1` → we move the file to `Sent/`.
- Phone-side code: `~/oplus-connect-research/oshare/dec/` (com.coloros.oshare);
  `m9/e.java` = MacTransferManager, `m9/g.java` = MsgDispatcher, `ja/d.java` =
  receive task. Only warn/error logs (`p0.f`) appear in logcat.

## Security notes (deep review 2026-11-21; earlier pass 2026-11-20)

**Pairing needs the user's OK.** The QR carries no secret, so anyone on the
LAN can run the SCP/UKey2 handshake with us. After SYNC_SECURE the app now
asks "Allow <phone> to connect?" (`approval.rs`; CLI asks on the terminal);
only Allow saves the KSC and answers the phone's INTERACT with "accept",
otherwise "reject". One request at a time, none while a phone is connected,
refused addresses blocked for 2 min. Verified with a rogue-phone test against
the running app (`cargo test -- --ignored live_`). Before this, any LAN host
could pair silently (and overwrite the real phone's key) and then receive
the PC clipboard, inject clipboard/files/notifications and redirect sends.

Also fixed in the 2026-11-21 review:
- Data channel: DataBus/service frames must be encrypted; the per-session
  message counter must increase (replays and retransmitted duplicates dropped).
- DataBus matched on the parsed message key: `phone_start_mirror` / IcdfStatus
  were substring matches, so notification text could trigger them.
- Terminal escape injection: all `println!` go through `util::clean`
  (control and bidi characters escaped); phone text reached the terminal raw.
- Logs no longer contain clipboard text, notification text, SDP or raw dumps
  unless `OPLUS_DEBUG=1` (an installed app's stdout lands in the journal).
- No more shared /tmp: QR and debug logs in `$XDG_RUNTIME_DIR/olink`
  (0700); a planted /tmp file could block startup or be symlinked.
- `crypto-bigint` timing advisory (RUSTSEC-2026-0387): ECDH moved from p256 to
  aws-lc-rs; p256, ring, axum, tower, hyper, reqwest, webpki-roots dropped
  (581 → 543 crates). Dead HTTP/WebSocket server modules removed.
- vite dev server removed (esbuild advisory; any website could query it);
  the app loads `src/` directly. npm audit: 0.
- CSP tightened; window capability reduced to event listen/unlisten.
- Parsers: SCP fragment-header chain, ICDF frame size (8 MB), protobuf varint
  lengths, CapEx slicing, HTTP header lines/counts, /bigmessage (16 MB).
- Only listening on 46888, 10150-10152 (was 10150-10160); max 64 connections;
  30 s idle timeout on probe ports.
- OPPO Share: phone's share server must be at the authenticated peer's IP.
- Clipboard: password-manager copies (`x-kde-passwordManagerHint`) never sent;
  setting to turn clipboard sync off; notification bodies markup-escaped;
  received file names lose bidi/zero-width characters; wl-copy reaped.
- Pairing dir 0700, key file written atomically (0600); a second app copy
  shows a banner instead of silently running without its server.

**Inherent / accepted** (OPPO's protocol or the phone, not fixable here):
- No pairing secret in the QR and no verification code shown on the phone,
  so an *active* attacker could still race the user's own scan (the user
  would see two requests / a failed scan).
- Data-channel AES-GCM keys/nonces depend only on (KSC, qc, qs, counter):
  both directions and all sessions count from 1 → nonce reuse. The SCP
  pairing session uses a fixed IV. Exploitable only by an on-path attacker.
- ODMF signalling after auth is plaintext from the phone (SDP incl. DTLS
  fingerprints): an on-path attacker could tamper with a cast.
- Our file server (46890) can't authenticate the phone's OPPO Share client
  (no credential in the protocol): another app on the phone could fetch a
  pending offer.
- The phone's own app-list HTTP server (8080…) has no authentication.
- Tauri's GTK3 stack: glib 0.18 unsound advisory (API unused); chrono and
  proc-macro-error unmaintained.
- No free-disk check for received files; the paired phone can send any amount.
- Phone reconnects may go through SCP again (`$isReConnect`; key type OOBKEY
  exists): if so, each reconnect asks for approval. Implementing OOBKEY would
  let the stored key prove a reconnect.

## Installed app (2026-11-21)

- **Two processes.** The background process (default; `--hidden` at login)
  holds the phone link, the tray and the cast window, and never creates a web
  view. **Open** starts `olink --window`, which hosts the page
  and talks to the background process over the private socket
  (`$XDG_RUNTIME_DIR/olink/instance.sock`, JSON lines, `ipc.rs`);
  closing the window ends that process, so all of WebKit's memory is freed.
  Measured (release build): 34-36 MB in the tray, ~266 MB with the window
  open, back to 34 MB after closing.
- Same socket = single instance (`instance.rs`): launching again just opens
  the window. Tray (Tauri `tray-icon`, AppIndicator): status line, Open, Quit.
- Idle work: none. Clipboard via `wl-paste --watch` (only while a phone is
  connected), Send folder via inotify, one 2-worker tokio runtime,
  `mallopt(M_ARENA_MAX, 2)` and `malloc_trim` after the window closes.
- Start on login: XDG autostart entry (`autostart.rs`, `--hidden`), written
  only by installed copies (not from a `target/` folder), setting in ⚙.
- Packages: `packaging/arch/PKGBUILD` (`makepkg -si`), AppImage via
  `npm run tauri build` (GStreamer bundled). ufw profile "Olink".
- Release build by hand: `cargo build --release --features tauri/custom-protocol`.

## Settings

`settings.rs`: `~/.config/olink/settings.json` with
`cast_quality` (smooth 720 / balanced 1080 / sharp 1440 wide), `scroll_mode`
(swipe / scroll), `desktop_notifications`. `OPLUS_CAST_SIZE`,
`OPLUS_CAST_SCROLL`, `OPLUS_NOTIFY` still override.

## Resume here

1. Same Wi-Fi; firewall allows TCP 10150-10160, 46888, 46890, 46892 and UDP 46900-46999 (ufw, persistent).
2. `./src-tauri/target/debug/olink net-probe pair` (add
   `OPLUS_CAST=1` in front for the screen-cast experiment), then
   `xdg-open $XDG_RUNTIME_DIR/olink/pairing-qr.svg`, scan it, and answer `y` to the pairing question.
3. Phone log: Developer options → Wireless debugging → `adb connect <ip:port>`
   (the port changes each time), then record `adb -s <ip:port> logcat -v time`
   *live* during an attempt (the buffer rolls over within minutes).
4. The app: `npm run tauri dev` (one copy at a time: fixed ports).
5. Next work: **remote PC control** (the phone controlling this PC).

## Research files (local only, not in git)

`~/oplus-connect-research/`: the phone's `AccessoryFramework.apk`, its jadx
decompilation (`apk-decompiled/sources/com/oplus/pantaconnect/…`; SCP server =
`pair/scp/e.java`, protocol = `pair/scp/d.java`, UKey2 = `com/google/security/
cryptauth/lib/securegcm/a.java`), and all session logs (btmon, logcat, probes).
**Do not commit or redistribute these.** They are OPPO's code and personal logs.

Other local state: the Windows partition was mounted read-only at `/mnt/windows`
(not persistent); a btmon capture is at `~/oplus-bt.log` (root-owned).
