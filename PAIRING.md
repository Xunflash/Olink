# O+ Connect discovery & pairing — the research log

> **How pairing actually works:** after scanning the QR, the phone connects to
> the PC over **Wi-Fi** (SCP on TCP 10152) and runs UKey2; the PC asks you to
> allow it, then keeps the key the phone sends. No Bluetooth, no OPPO account.
> The spec is [SCP.md](SCP.md); the crypto, [CRYPTO.md](CRYPTO.md).
>
> This page is how that was found, in order. The early sections, read from the
> Windows app's logs, concluded pairing ran over Bluetooth. The sections dated
> 2026-11-19 show the phone's own code and traffic proving it runs over Wi-Fi.
> Both are kept: the Windows-side findings (the QR format, discovery, the
> same-account path) still hold; only the transport conclusion changed.

Recovered first from the Windows app's own logs (`pantaconnect/pantaSdkDlog.log`,
`pantaServiceDlog.log`) and its Electron `render.log`: how a phone and PC find
each other and establish trust, *before* the file transfer in `PROTOCOL.md`.

**What still holds from this part:** discovery and addressing are fully
recovered, and there are two trust paths: **same account** (a silent OPPO
account-match handshake) and **cross account** (needs your confirmation, no
OPPO account). Olink uses the cross-account path.

## The QR code is just an address, not a secret

When the phone isn't auto-discovered, the PC shows a QR. It is a plain URL:

```
https://pc-assistant-eu.allawnofs.com/h5/index.html?param=<oconn-json>
```

with this `oconn` payload (full, from `render.log`):

```json
{"oconn":{
  "bm":   "00:11:22:33:44:55",      // PC Bluetooth MAC
  "pm":   "00:11:22:33:44:56",      // PC Wi-Fi-Direct (P2P) MAC
  "dvd":  "1A2B3C4D5E6F",            // PC device id
  "name": "My_Laptop",
  "model":"B5339A",
  "addr": "192.168.x.229:46888",    // PC ONet listener  <-- the key field
  "d_type":6,                        // 6 = PC
  "ver":  2,
  "acc":  "1a2b3c",                  // OPPO account hash (see below)
  "cp":   "win",
  "lang": "en-GB"
}}
```

The phone scans it, reads `addr`, and connects to the PC there. A Linux client
can generate the same QR with its own `addr`/ids — no BLE needed on a shared LAN.

## Discovery (same account, same network)

Usually no QR is needed. The phone shows up in the PC's device list by itself:

```json
{"deviceId":"A1B2C3D4E5F6","deviceName":"OPPO Find X9 Ultra","connectType":16,
 "ip":"192.168.x.156","scpIp":"192.168.x.156","isSameAccount":true}
```

* Discovery runs over **ONet, a UDP event bus** (libuv `uv_udp_send`, appearing
  as `oafEvtBus` in the logs), with `StartAdvertisementInternal` beaconing on
  two transports: `connType 1` (LAN/Wi-Fi) and `connType 8` (Wi-Fi Direct).
* The PC's **ONet listener** binds several ports — the QR's `addr` uses
  **46888** (`AcceptListenerThread … Listen Port[46888]`, `conType 1`).
* The Electron UI drives all of this through a **local HTTP-over-named-pipe API**
  (`\\.\pipe\dspipc`): `/get_qr_info`, `/discovery_query`, `/probe_devices`,
  `/enable_senseless_discovery`, with base64 params. Useful as a ready-made
  control surface if you build on top of the real daemon.

## The trust gate: account-match handshake

Once connected, the two run an **account-match** exchange (ONet D2D messages,
`data_sync_msg_module: 21`, `type: account_match_msg_type`). The body is a
hex-encoded JSON with an `op` sequence:

```jsonc
// op 0 — version init
{"ver":[256,512],"op":0}

// op 200 — keyed challenge
{"type":0,
 "salt":"AAAA<salt: 32 bytes, base64>AAAAAAAAAAAAAA=",   // base64, 24B
 "id":"BBBB<id: 32 bytes, base64>BBBBBBBBBBBBBBBB=",     // base64, 32B
 "keyId":"1_<64 hex digits>",
 "keyListVer":1, "region":"GB", "ts":1794870000000, "op":200}

// op 204 — encrypted token
{"ets":"<token, base64>","op":204}
```

And a companion message carries the account identity:

```json
{"randomid":"<64 hex digits>","switch":1,
 "device_id":"A1B2C3D4E5F6","account_hash":"1A2B3C","is_log_triggered":false}
```

What this means:

* Both devices hold a shared **account key list** (identified by `keyId`,
  `keyListVer`), provisioned when you sign into your OPPO/HeyTap account in the
  app (`login_info.dat`, `region_info.dat`). `account_hash 1A2B3C` == the QR's
  `acc`.
* `salt` + `id` + `ets` are a salted challenge/response (the ECDH/ECDSA +
  AES-GCM primitives seen in `pantaConnSDKDll`) proving both sides possess the
  account key. `mAccountMatchLevel: 0` = same-account.

**So the same-account gate is account possession, not a per-device secret.** A
Linux client on the same account would need that account's key material — which
is why we do **not** target this path.

## The cross-account path (CAPTURE-VERIFIED — the way in)

We ran the capture: signed **out** of the OPPO account on the PC, left the Find
X9U signed **in**, and paired. `render.log` confirms the connection came up with
`"is_same_account":false` (full `connectCallbackInfo`:
`{"device_id":"A1B2C3D4E5F6","device_name":"OPPO Find X9 Ultra","connect_type":16,
"is_same_account":false,"device_type":8,...}`, phone model CPH2841).

On that connection, in `pantaServiceDlog`:

* **`account_match` message count = 0.** The account-match module appears only
  with `pairType: -1` (not selected). The account key is never exercised.
* The active modules are `14102` / `15001` / `15004` with **`pairType: 0`**, and
  the trust work happens in the native **`authentication`** module.

### Reading the Windows logs: two layers (transport superseded, see 2026-11-19)

A second, cold capture (PC signed out, both sides deleted, re-paired at 19:25
with the on-screen **"Allow this device to connect to 'OPPO Find X9 Ultra'?"**
dialog) showed the real shape. The trust is NOT established by the WiFi
`authentication` stage — it's established earlier, over **Bluetooth fast-pair**,
and the WiFi stage only re-proves it:

```text
  ┌─ LAYER 1: Bluetooth fast-pair (module: fastPair) ──────────────────────┐
  │  • BLE connect + the "Allow this device?" dialog = the HUMAN CONFIRM.   │
  │  • UKey2/ECDH key agreement → derives KSC (the shared session key).     │
  │  • EVT_SAVE_KSC_INFO_REQ → keyMgrSaveKsc "save ksc to memory success"   │
  │  • keyMgrSavePeerDeviceId "67 a6 6e 46 6c 66" → PeerDeviceId table.     │
  │    ^ this persistent record is why later reconnects are SILENT.         │
  └────────────────────────────────────────────────────────────────────────┘
                                   │  KSC now held by both sides
                                   ▼
  ┌─ LAYER 2: WiFi/ONet auth (module: authentication) ─────────────────────┐
  │  EVT_ACCESSORY_CREATE_IND → EVT_ACCESSORY_IDENTITY_SUCCESS              │
  │  getKsc "Get KSC success"   (loads the key from layer 1)                │
  │  generateServerChallengeMac / generateClientChallengeMac               │
  │  checkRemoteParams: RC == generateRC ?   →  "check succeed!"            │
  │     8-byte RC, CAPTURED equal on both sides:                           │
  │        warm run: f6 7b ce 14 40 96 8e 06                                │
  │        cold run: 53 28 0a 12 cf 05 27 48                                │
  │  AUTH_SERVER_WAIT_FOR_CONFIRM → checkRc2 "succeed" → "auth success"     │
  │     (this gap is ~7 ms — it does NOT wait for a human; the confirm      │
  │      already happened in layer 1)                                       │
  └────────────────────────────────────────────────────────────────────────┘
                                   ▼
          AES-GCM D2D session  ──▶  the transfer protocol in PROTOCOL.md
```

Reading of the primitives:

* The whole thing is modelled as **accessory authentication** (`EVT_ACCESSORY_*`,
  `authParseAccessoryRequest`, "accessory id") — the same family as Google Fast
  Pair / Apple MFi accessory auth.
* **`KSC`** ("Key Session Credential") is the symmetric key agreed over BLE in
  layer 1 and then used to key AES-GCM. It is **saved to a key manager + a
  `PeerDeviceId` table**, so it survives — the first pair prompts, every
  reconnect is silent. This exactly matches the observed behaviour ("I didn't
  press trust, just connected over Bluetooth").
* **`RC`** is an **8-byte** value both peers derive from the KSC and compare;
  equality is the re-proof on the WiFi side. CAPTURE-VERIFIED equal on two
  independent sessions (values above).
* **`account_match` (module 21) is NOT the gate.** On the signed-out PC it still
  appeared — but *after* `auth success`, with `i32Encrypt: 0` and no `keyId`.
  It's account-identity metadata, exchanged if present, ignored if absent. The
  connection completes fully without it.
* The exact curve + HKDF labels that derive KSC are **not in the logs** (neither
  `pantaServiceDlog` nor `pantaSdkDlog` print key material). They live in
  `pantaConnSDKDll` — the `cryptoUkey2DoKeyAgreement` / `cryptoUkey2Hkdf`
  exports. Working assumption: ECDH P-256 + HKDF-SHA256 → AES-256-GCM.

## What the Windows binaries showed (2026-11-18)

Static analysis of `pantaConnSDKDll.dll` and `pantaChannelService.exe` got the
key exchange right: **stock Google UKey2, cipher `P256_SHA512`** (P-256 —
`EC_KEY_new_by_curve_name` is always called with NID 415 — and a SHA-512
commitment), **HKDF-SHA256** with the stock salts `UKEY2 v1 auth` /
`UKEY2 v1 next`, and a build path showing Google's code is vendored
(`utils\ukey2\protobuf_cpp\securemessage.pb.cc`).

Three conclusions drawn from the Windows side alone turned out wrong, and are
corrected in CRYPTO.md: pairing doesn't run over Bluetooth (it's SCP on TCP
10152), the session isn't AES-CBC + HMAC (it's AES-256-GCM, plus OPPO's
`ivSpec`), and the 8-byte value compared on reconnect isn't the UKey2
verification string (it's the HMAC-SHA512 proof of the KSC on the data
channel). The build plan that followed assumed Bluetooth; the sections below
are where that changed.

## GATT layout — CAPTURE-VERIFIED on Linux (2026-11-19, Find X9 Ultra CPH2841)

Read directly from the phone's GATT database (ATT over BR/EDR, L2CAP PSM 31,
using `ble-probe att <MAC>`). **This corrects the earlier assumption: the PHONE
is the GATT server; the PC is the central/GATT client.** `0xAA16`/`0xAA17` are
*characteristics* inside the phone's service `0xAA15`, not services the PC hosts.

```text
SERVICE 0xAA15   handles 0x0090-0x0098
  CHAR 0xAA16  value 0x0092  [read notify indicate]   phone -> PC
       DESC 0xAA18 (0x0093, vendor)   DESC 0x2902 CCCD (0x0094)
  CHAR 0xAA17  value 0x0096  [write-without-response]  PC -> phone
  CHAR 0xAA20  value 0x0098  [read]   (empty when idle)
SERVICE 0xAFAF   0x009a-0x00bb  chars 0x0001,0x1001-0x1005,0x1101..0x1501 [read write notify]
SERVICE 0xBB15   0x0109-        char 0x9998 [read write]
```

SDP (classic) records on the phone, same family:

| UUID | Name | Transport |
|---|---|---|
| `0xAA15`, `0xAFAF`, `0xBB15` | — | ATT over BR/EDR (PSM 31) |
| `a49eaa15-cb06-495c-9f4f-bb80a90cdf00` | SecureAFP | RFCOMM ch 6 |
| `a49eee15-cb06-495c-9f4f-bb80a90cdf00` | InSecureAFP | RFCOMM ch 5 |
| `a49ecc15-cb06-495c-9f4f-bb80a90cdf00` | InSecureAFP | RFCOMM ch 7 |

Phone LE advertisement while O+ Connect is open: manufacturer `0x079A` (OPPO)
`af30<…>1a2b3c<…>` — contains the account hash `1a2b3c`
(= QR `acc`); plus service data `0x686B`: 6 rotating bytes + `08` + device name.

Note: when opening L2CAP PSM 31 from Linux, wait ~500 ms after connect() before
the first PDU, or the kernel drops the channel mid-configuration.

### First message: phone → PC "OAFP" hello (CAPTURE-VERIFIED)

Subscribing to the AA16 CCCD (write `0x0003` to handle 0x0094) makes the phone
immediately push one 104-byte notification — before the PC writes anything.
It is a vendor **OAFP** ("OPLUS Advanced Fast Pair", cf. SDP `SecureAFP`) frame,
not yet UKey2:

```text
67                      length of the rest (103)
01 00 0a                header (version/type? — TBD)
"OAFP_<31 hex digits: device id>"  36-char ASCII id, then 0x21 '!'
0c                      entry count = 12
01 00007fc4   02 00eb   03 03fe   04 2710 (=10000)   05 000a
06 07 "CPH2841"   07 04 "OPPO"   08 12 "OPPO Find X9 Ultra"
0a 08   0b 01   0c 45   0d 00
2d 65                   trailer (not a standard CRC16 — TBD)
```

What the PC must write back on AA17 is the next unknown; source of truth is the
Windows `fastPair` module (static analysis of the installed binaries).

### QR first-contact experiment from Linux (2026-11-19) — negative result

Showed an `oconn` QR (fresh `dvd` 4C494E555801, real `bm`, LAN `addr`
192.168.x.107:46888) and listened on TCP+UDP 46888, with a mirrored GATT
server (service AA15 > AA16/AA17/AA20) advertising, and btmon running.
The phone accepted the QR, showed "press Allow on the PC", then timed out with
"connection failed". **Zero traffic reached us**: no TCP/UDP on 46888, no LE
connection, no new L2CAP/RFCOMM channel. Combined with the Windows log
(`createQRCodeInfo: WfdStatus:2` → `startWfdThread` → `p2pForPcStart` →
`fpWfdAdverStatusNotify Mac/ServerIp/DeviceId/ModelId`), the QR path most
likely expects the PC to be discoverable over **Wi-Fi Direct (P2P)** using the
QR's `pm` MAC. Next: read the phone's own logcat during a QR attempt to confirm.

### The phone's side of the QR flow — from its own logcat (2026-11-19)

Read over `adb logcat` (wireless debugging). O+ Connect's engine is
`com.heytap.accessory` ("PTC" = PantaConnect, tags `PTC.*`), UI in
`com.oplus.linker` ("Device Connect"). After scanning our QR:

1. `OutOfBandDeviceEvent` parses it: `device:4C494E555801, bt address,
   p2p address, btName:Linux, wifiIpExtra:192.168.x.107:46888, deviceType:6`.
2. It opens an **SCP connection** as **Seeker**: `connectScp … ipv4=<qr ip>,
   port=10152, type=WLAN_TCP`, in parallel with a `P2P_TCP` (Wi-Fi Direct)
   attempt. **Port is 10152, not the QR's 46888.**
3. LAN discovery also tcp-probes **port 10150** on known PCs.
4. Each WLAN_TCP attempt: `SocketTimeoutException … port 10152 after 5000ms`
   (×3) → `scp_connect_result … key_type=UKEY2, scp_stage=SocketConnect`.
   The timeout was our ufw firewall dropping 10152.

So: the PC listens on **TCP 10152** (SCP) and the handshake on it is **UKEY2**.

### SCP framing on TCP 10152 — CAPTURE-VERIFIED (2026-11-19)

With 10150-10160 open, the phone connected to TCP **10152** and sent:

```text
header (12 B): 40 30 | 00 36 | 00 02 | 00 00 | 7b 08 ad 12
               magic "@0"  len(payload, BE u16)  type  flags?  conn/session id
payload (protobuf):
  2 {                                   # request
    1: -332202674                       # request id (int64, negative)
    2: "active_connection"              # channel name
    3: "com.heytap.accessory"           # package
  }
```

After 5 s without a reply (type 0x0000, same session id):

```text
  1: 65535
  2 { 1: -332202673   2: 2514   3: "Timed out waiting for 5000 ms [TimeoutCancellationException]" }
```

So the first exchange on 10152 is a channel-open RPC; the PC must answer within
5 s. Reply format: TBD from the phone's `AccessoryFramework.apk`.
