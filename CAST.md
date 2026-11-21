# Screen casting (phone → PC): research notes

_Started 2026-11-20. **Working 2026-11-20 10:36** (commit fce3bed): phone screen + audio on Linux via `OPLUS_CAST=1 … net-probe pair`._

> **Update (same day): the modern PC path is NOT the Miracast/WebSocket one.**
> It is **ODMF = WebRTC** with OPPO JSON signalling, triggered over the DataBus
> we already speak. See "Modern path: ODMF (WebRTC)" below. The older sections
> describe the legacy path (Wi-Fi Direct + WebSocket pinned to OPPO's
> `server.cer` for 192.168.137.1, which we can't serve without OPPO's private
> key), kept for reference.

## Who does what on the phone

| Piece | App | Notes |
|---|---|---|
| Orchestration | `com.oplus.linker` | `PcCastEngineService` ("PcCastEngine" engine alias), `CastSceneManager`, `WebSocketScene` |
| Capture + encode + stream | `com.oplus.cast` (`/product/priv-app/HeyCast/HeyCast.apk`) | Java: `z2/q.java` (SynergyManager), `RemoteDisplayNative`; native: `libheycastcore.so` |
| Input back to phone | `com.oplus.linker` | `app:inputservice` (gRPC `InputServiceGrpc`), plus WFD UIBC |

Decompiles (local only, not in git): `~/oplus-connect-research/cast/dec/`
(HeyCast) and `~/oplus-connect-research/linker/dec/` (linker).

## Media transport: it's Wi-Fi Display (Miracast)

`libheycastcore.so` is AOSP's `WifiDisplaySource` with OPPO extensions:
RTSP control (`rtsp://localhost/wfd1.0`, M1–M7, GET/SET_PARAMETER) and RTP
(MPEG-TS) video, **AVC or HEVC** (`get reconfig codectype(0 avc 1 hevc)`),
optional audio, **UIBC** for input (`M4 uibc`), optional TCP transport
(`setIsTCPDatagramConnection`), optional AES content protection
("Sink doesn't report its aes key and iv").

OPPO sink parameters it asks for (all optional, "Sink doesn't report …"):
`wfd_pc_display_mode`, `wfd_car_display_mode`, `osc_display_mode`,
OSC ROTATES / FOLD ROTATES / AUDIO ENCRYPT / BACKSTAGE PROJECTION FULL,
`pad_device_info`, VS and OVM capability, `wfd_audio_latency`.

Java entry: `RemoteDisplayNative.listen(deviceInfo, pkg, …)` →
`nativeListen("<mDeviceIp>:<mDevicePort>", pkg, flag)`, flag 5 = SYNERGY_PC.
`mDeviceIp` is the **PC's** IP and the native code checks incoming RTSP
connections against an expected IP ("incoming rtsp client connection not
match expected ip"), so the phone appears to run the RTSP server on
`mDevicePort` and accept only the PC. **To confirm on the wire.**

## How a PC cast is triggered

1. PC publishes a relay list on the DataBus topic
   `Oplus_HeySynergy_PadConnect_CastMaterial` (same mechanism as clipboard,
   `scp/pcclip.rs`), `TaskType` = `P2P_CONNECT_BY_START_MIRROR` (or
   `NO_SENSE_CAST`, `P2P_CONNECT_BY_RELAY`). Keys read by
   `CastMaterialReadRunnable`: `WlanStatus`, `P2PStatus`, `RemoteDvd`,
   `IcdfStatus`, `CastPort` (= RTSP port), `SourcePkgName`, `RelayStatus`,
   `VDResolution`, `WebSocketPort`. Missing `WebSocketPort` ⇒ treated as a pad.
2. That starts the `PcCastEngine` + share engines with those values.
3. `WebSocketScene.createWebsocketForCast`: the **phone connects to a
   WebSocket server on the PC** at `WebSocketPort` (default **8080**). This is
   the cast control channel. Last night's logcat already showed the phone
   trying and failing (`WebSocketConnectManager … invalid_local_ip_addr`,
   `SynergyWebsocketListener onFailure`).
4. Then HeyCast starts the WFD source for the PC.

## Modern path: ODMF (WebRTC) — the one to implement

Code: `com/oplus/linker/pc/cast/` in linker (no WebSocket), HeyCast's
`com/oplus/cast/engine/impl/odmf/`, and the system library
`/system_ext/framework/oplusex/com.oplus.odmf/odmf.jar` +
`/system_ext/lib64/oplusex/com.oplus.odmf/libortc_so.oplus.so` (a Google
WebRTC fork: DTLS-SRTP, BUNDLE, SCTP, H.264/H.265/VP8, Opus). Decompile:
`~/oplus-connect-research/odmf/dec/`.

**Trigger (DataBus, `CastSceneManager.handleReceiveData`).** PC sends key
`rsp_odmf_key` with JSON `CastParams`: `port` (our signalling server port),
`odmf_auth_info` (JSON string, below), `clientId`, `server_ip`,
`privacyProtect`, optional `component_name` (cast one app), `notifyKey`.
Phone then starts the cast (`rtspPort` 7236 is set but WebRTC carries media).
Other keys seen: `pc_cast_ability`, `phone_cast_ability`, `phone_start_mirror`,
`mirage_start`/`mirage_stop`, `screen_record_authorize`, `cast_ability_sync`,
`pc_control`/`accept_pc_control`, `input_service`. DataBus topics include
`Oplus_Cast`, `Oplus_PcConnect`.

**Envelope** (`CastDbsReceiver`): DataBus topic **`Oplus_Cast`**, payload
`{"key": "cast_ability_sync", "value": "<CastMessage JSON>"}` (allowed keys:
`cast_ability_sync`, `key_events`). `CastMessage` = `{"msg_cmd", "msg_body",
"msg_type", "msg_value", "clientId"}`; `handleReceiveData(msg_cmd, msg_body)`.
So the trigger is `msg_cmd = "rsp_odmf_key"`, `msg_body = <CastParams JSON>`.

**Auth info (PC generates, `AuthUtils.convertAuthInfoToJson`):**
`{"id": b64(8 random bytes), "public_key": b64(X.509 EC P-256 pubkey),
"timestamp": "<ms>", "auth_version": 1}`. Phone (`generateAuthInfoFromJson`)
makes its own P-256 key, ECDH → `sharedKey` (AES).

**Signalling transport:** phone = `OdmfSocketClient` (`odmfr/odmfd.java`)
TCP-connects to `server_ip:port` (50 tries, 1 s apart). Frames
`[u16 BE length][UTF-8 JSON]`. Server side reference implementation is in the
same jar (`odmfr/odmfc.java` OdmfSignalingServer, `odmfr/odmfh.java` channel).

**Signalling auth (`odmfr/odmfe.java`, SigIdentityAuthHelper):**
server → `{"cmd":"OdmfAuthRequest","auth_version":1}`; client →
`OdmfAuthResponse` with `auth_info` = `{timestamp, iv, public_key (client),
encrypt_cipher = AES-GCM(sharedKey, iv, aad=timestamp?)(id)}`; server checks
decrypt == id, replies `{"cmd":"AuthSuccess", timestamp, iv, encrypt_cipher =
AES-GCM(sharedKey)({"id","key": b64(AES-256 session key)}), auth_version:1}`
(or `AuthFail`). Then `PairRequest`/`PairSuccess`, `ping`/`pong` every 3 s,
`TimeSyncServer`/`TimeSyncResult`. Payload messages are
`{"cmd":"send","msg": "<json>"}` where msg has `type` = `offer`/`answer`/
`candidate`/`remove_candidate`/`bye`/`bye_ack`/`control`… Encrypted message
format after auth: `[0x01][13-byte ms timestamp][12-byte IV][AES-GCM ct]`
with the session key and AAD = timestamp.

**Crypto, exact:** ECDH P-256, raw 32-byte shared secret used directly as the
AES-256 key (no KDF). AES/GCM/NoPadding, 12-byte IV (auth_version 1), 128-bit
tag, **AAD = the `timestamp` string's UTF-8 bytes**. All values base64.

**Receiver on Linux:** GStreamer `webrtcbin` (installed) → depay → `vah264dec`
/ `vah265dec` → `waylandsink`. Missing packages: `gst-plugins-good`,
`gst-plugins-base`.

## Experiment 1 (2026-11-20, commit dc91cef, `OPLUS_CAST=1`)

Logs: `~/oplus-connect-research/logs/cast1-pc.log`, `cast1-logcat.txt`.

- `rsp_odmf_key` on `Oplus_Cast` **works**: the phone showed a casting
  permission prompt, then published on `Oplus_Cast` (`cast_ability_sync`):
  `navigationbar_state {state:3}`, `deviceInfo {foldTypeValue:0,
  densityDpi:640, isFoldDevice:false}`, `screen_record_authorize
  {allow_value:2}` then `{allow_value:0}`, `resolution {resolution_value:
  14403168}` = width×10000 + height = 1440×3168.
  Android's "App content hidden from screen share" notice confirmed
  MediaProjection was running.
- The phone opened **two** signalling connections (`local_user_name`
  `heycast_odmf`, `local_transportbus_id` 59748864 and 0000062856328,
  `remote_transportbus_id` empty). **Both passed auth** (our ECDH/GCM is
  right), sent `PairRequest`, got our `PairSuccess`, then only `ping`s.
- **No `offer` arrived.** The phone is waiting for the PC peer.

Hypotheses for next session (check odmf.jar `odmfr/odmfd.java` client after
PairSuccess, and `OdmfEngineImpl` for who creates the offer):
1. The PC side is the **caller**: the PC peer must send `{"cmd":"send","msg":
   {"type":"offer",…}}` (recvonly video/audio) and the phone answers.
2. `PairSuccess` must name a real paired peer: in OPPO's relay the PC's own
   WebRTC client is a second socket; `remote_transportbus_id` probably has to
   match something (maybe the other phone socket pairs with the first?).
3. A `start_play` / `TimeSyncServer` message may be needed first.
4. ODMF logs: find its logcat tag (`com.oplus.odmf.log`), grep by HeyCast pid.

## Experiment 2 (2026-11-20, commit 8404a85: + `pc_codec` H264_HIGH)

Logs: `~/oplus-connect-research/logs/cast2-*`. Phone ODMF logcat tags:
`OdmfEngineImpl`, `NearTransportBus(Base)`, `OdmfSignalingClient`,
`OdmfSocketClient`, `PeerConnectionClient`, `SignalingUtils` (HeyCast pid;
Android drops lines over a 300-row quota, so start logcat before scanning).

**Answer: the phone is the ANSWERER.** `create peer connection, isHost:
false`. The PC must send the WebRTC **offer** (`{"cmd":"send","msg":
"{\"type\":\"offer\",\"sdp\":…}"}`); the phone answers. Hypothesis 1 confirmed.

- Phone ODMF `sdk_version` 16.7.2, Android 16, model CPH2841.
- Two transport buses, one signalling socket each: **ONLY_VIDEO** (id e.g.
  52655515) and **ONLY_AUDIO** (`createTransportBusForAudioAndConnect`). So
  two PeerConnections: offer recvonly video on the video socket, recvonly
  audio on the audio socket (tell them apart by which socket; the
  `local_transportbus_id` in each OdmfAuthResponse).
- `Preferred video codec: H265` at creation (before our `pc_codec`);
  `pc_codec` → `PeerConnectionClient.odmfb(VideoCodec)` should switch it.
  Offer H.264 (and maybe H.265) and see what it picks.
- The phone also measures RTT to the PC every second (`detectRtt`); fine.

## Working flow (2026-11-20)

1. DataBus `Oplus_Cast` → `rsp_odmf_key` (our signalling port + auth info).
2. Phone opens two signalling sockets (video, audio); auth, PairRequest →
   PairSuccess; we send `pc_codec`.
3. **PC offers** (webrtcbin; recvonly H264/H265 + a data channel on the video
   bus, Opus on the audio bus); phone answers (picked H.265), ICE + DTLS.
4. Phone opens its data channel and sends `{"SET_PARAMETER":[{"uibcIP":…}]}`;
   on MEDIA_CONNECTED it sends `{"COMMAND":"interaction"}` ("start media
   consult"). We answer with sink consult params
   `{"COMMAND":"SET_PARAMETER","width","height","fps","foldRotatesWithContent","rotatesWithContent"}`
   **on our own data channel** (the phone adopts it; its own channel never
   received our messages). Phone replies `SET_PARAMETER {rotatesWithContent,
   scale:0}` and `ROTATION {rotation:0}`, creates its virtual display, streams.
5. On stop: `{"COMMAND":"REMOTE_DISCONNECT","error":"Source Release"}`.

**Input (phone control, commit 5af1710+, `scp/uibc.rs`):** binary UIBC on our
data channel, format from HeyCast `x2/a.java` (MacUibcPolicy; we're
SYNERGY_MAC): `[0x81][0][N=0][0][0][eventType]` + payload + 8-byte BE input
time (stripped by the phone's data channel). Touch (2): action u32, count u8,
per pointer id/x/y u32 + 2 pad, then width u16, height u16, deviceId u32 (999).
Key (0): action u8, Android keycode u32, meta u32, deviceId u32. Scroll (3):
x, y u32, w, h u16, hscroll, vscroll i32, deviceId. Window events come from
GstNavigation; **waylandsink has no scroll support**, so the window is
glimagesink (`OPLUS_CAST_SINK` to override). Trackpad deltas are fractional
and accumulated. Mapping: click/drag = touch, wheel = scroll, right click =
Back, middle click = Home, keys → Android keycodes. Tap/drag/keys confirmed
working; trackpad scroll fix (glimagesink) not yet confirmed.

**Video window vs input (2026-11-20):** glimagesink on Wayland: smooth
scroll, **no keyboard** (no wl_keyboard). glimagesink via XWayland: keys,
**no scroll events**. gtksink's own window: no scroll, key names empty.
**Fix (default now, needs `gst-plugin-gtk`):** our own GTK3 window
(`own_window`/`build_window` in castrx.rs) holding gtksink's widget; we handle
smooth scroll + keys ourselves and send them to the sink as GstNavigation
events, so the same pad probe turns them into UIBC. Clicks/drags come from
gtksink's widget. Confirmed: window, clicks/drags and Escape = Back work.
`OPLUS_CAST_SINK=<sink>` still picks a plain sink. gstreamer-rs (glib 0.21)
and gtk 0.18 (glib 0.18) differ, so the widget crosses as a raw pointer.

**Swipe mode (default since 2026-11-20; `OPLUS_CAST_SCROLL=scroll` for UIBC scroll events):** trackpad scroll → one-finger drag.
Touch-down waits for 12 px of motion (direction known, no stray taps); a swipe
moving away from a nearby edge (90 px) starts on that edge (bottom-up = Home,
sides = Back); otherwise the finger gets ≥ 50% of the screen to travel; lift
25 ms after the last scroll event (Android zeroes fling velocity after 40 ms
still). Scale `OPLUS_CAST_SWIPE_SCALE`: GTK deltas are ~12× smaller than
glimagesink's — at 1.5 the GTK swipes moved only ~50 px (user had to
click-drag), so the GTK default is now **18 — confirmed smooth (2026-11-20)**;
1.5 for glimagesink. Vertical swipes get 70% of the screen (`SWIPE_ROOM_V`):
from mid-screen (50%) a swipe up did not open the drawer; starting ~70% down
(like adb `input swipe 720 2200 720 900`) it does. Downward swipes start at
least 25% down (`SWIPE_TOP`): from y≈200 they landed on the Settings title bar
and didn't scroll. Confirmed working: drawer, shade, home pages, Settings
scrolling, clicks, keyboard, Escape = Back, Super = Home.

**Screencast entry on the phone** (2026-11-20, commit 8c74357): Settings →
Device connect → PC → Cross-device features → Screencast appears only when
the PC's device properties have `CastAbility` ≥ 1000 (or `PCVersion` ≥ 3.1.0
for device type 6) — `MyPcDeviceOnPhonePreference.isCastSupported`. Set by
publishing `{"key":"pcAbility","value":"<JSON>"}` on DataBus topic
**`Oplus_MacConnect`** (`MacDbsReceiver` → `MacSceneManager.dealwithPcAbility`;
every `getString` field must be present, see `odmf::pc_ability_payload`).
Tapping Screencast makes the phone publish `phone_start_mirror` on the same
topic; we answer with `rsp_odmf_key`. `OPLUS_CAST=manual` waits for the tap,
`OPLUS_CAST=1` also auto-starts 8 s after connecting.

**Single-app cast** (2026-11-20, confirmed): `rsp_odmf_key` with `component_name`
= a package name makes the phone run that app on a virtual display and cast
only it ("mirage", `CastSceneManager` → `MirageSceneImpl.startMirageCast`); the
phone's own screen stays free. The app offers recent apps (`all_recent_app` on
`Oplus_MacConnect`) and apps seen in notifications. Android's "A single app"
choice in the phone's casting prompt stays greyed out: HeyCast's
`RecordVideoPermissionActivity` asks with
`MediaProjectionConfig.createConfigForDefaultDisplay()` (whole screen only), so
the PC can't enable it.

**Full app list** (2026-11-21, confirmed, `scp/phoneapps.rs`): after
`pcAbility` we publish `{"key":"MacClientVersion","value":"3.1.0"}` on
`Oplus_MacConnect` (linker `MacDbsReceiver` → scene type 57 →
`OcastSdkWrapper.initHttpAndAppInfo`). The phone starts a plain-HTTP server
(`HttpServer`, ports 8080/8111/8222/8333/8444, no auth) and publishes
`http_msg` `{"ip","port"}`. `GET /data/all_white_app` returns
`ResultData{code,message,data}`, `data` = JSON string `{"all_white_app":
{pkg:{name,name64,icon}}}`: installed apps on the mirage allow-list, icons
base64 WebP. We connect only to the phone's own IP (the message's `ip` is
ignored), cap the body at 32 MB, validate package names and re-encode icons
after checking magic bytes. Same server: `all_recent_app`, `get_wallpaper`,
POST `search_app` / `install_app`.

**Next:** installed app (bundle), polish.

Tuning: 200 ms jitter buffer (`OPLUS_CAST_LATENCY`), NACK, 1080×2376@60 by
default (`OPLUS_CAST_SIZE=WxH[@fps]`), leaky video queue.

Known issues: first run laggy/choppy (fixed by tuning above). Phone and PC were on different
subnets (192.168.170.x / 192.168.178.x, RTT 10-600 ms).

## Next steps

1. ~~Crypto details and DataBus envelope~~ (done).
2. ~~Signalling server + auth + `rsp_odmf_key`~~ (works). Get the phone to
   exchange SDP (see Experiment 1 hypotheses).
3. **PC creates the offer** with GStreamer `webrtcbin` (recvonly video
   H264/H265 on the video socket, recvonly Opus on the audio socket), send
   it + ICE candidates, apply the phone's answer, show video in a window.
   Needs `gst-plugins-good` + `gst-plugins-base` and the gstreamer-rs crates
   (`gstreamer`, `gstreamer-webrtc`, `gstreamer-sdp`).
4. Later: input (`input_service` / `app:inputservice`), audio (Opus).
