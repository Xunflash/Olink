# O+ Connect wire protocol — capture-verified

Confirmed against `ovmsocketlog.log` (the app's own `DEBUG` log, which prints
every control message, URL and port in plaintext). Examples below are real
lines from a OnePlus ↔ Windows PC on the same LAN. No Wireshark or TLS
decryption was needed.

## Roles & transport

* **Control channel:** WebSocket on path `/websocket`, over TLS (`wss://`).
  Each side runs both a client and a server (DotNetty). IDs/ports are ephemeral
  and chosen per session.
* **File channel:** plain HTTPS GET to the sender's `host:port` (same host as
  the control socket). Routes: `/download`, `/thumbnail`, `/bigmessage`,
  `/versionNegotiation`.
* Observed endpoints: PC `192.168.1.209`, phone `192.168.1.156`; the phone's
  HTTP server bound to rotating ports like `49371`, `50435`, `52986`. A
  `172.30.243.240` address also appears — the Wi-Fi Direct / P2P interface used
  when the two are not on the same LAN.

## Control-message framing

```
<kind>:<id>:<taskName>?<json>
```

* `kind` ∈ `action` | `ack`   ·   `id` is a small int (always `0` observed)
* `taskName` ∈ `sendRequest` | `downloadRequest` | `cancel` | `status` | `versionNegotiation`
* everything after `?` is the JSON body

Real frames:

```
action:0:versionNegotiation?{"version":2,"protocolVersion":4}
ack:0:sendRequest?{"taskId":"1869b34a-67aa-4dbd-9c77-7074234d8901"}
ack:0:status?{"taskId":"1005444519"}
```

## 1. Version negotiation (first thing after connect)

```
action:0:versionNegotiation?{"version":2,"protocolVersion":4}
```

Log: `[PROTOCOL_VERSION] negotiated remote version=2, remote protocolVersion=4,
local protocolVersion=4`. We speak `protocolVersion = 4`; the phone advertised
device `version=2`.

## 2. File offer (`downloadRequest` body)

Sent when a side offers a file; the peer replies `ack:0:downloadRequest?{...}`.
This is the full, verified shape:

```json
{
  "taskId": "0d668e0d-de55-40ef-b4f9-58a4b0694652",
  "senderId": "A1B2C3D4E5F6i1Tx",
  "senderName": "MYPHONE",
  "fileName": "IMG20260101120000.jpg",
  "mimeType": "image/jpeg",
  "fileCount": 1,
  "totalSize": 5843203,
  "thumbnail": "/thumbnail?taskId=0d668e0d-de55-40ef-b4f9-58a4b0694652",
  "thumbnail_height": 320,
  "thumbnail_width": 320,
  "file": [
    {
      "name": "IMG20260101120000.jpg",
      "size": 5843203,
      "mimeType": "image/jpeg",
      "fileId": "68944f59-eb0c-4b08-977d-e188ca4347b3",
      "filePath": "/storage/emulated/0/DCIM/Camera/IMG20260101120000.jpg",
      "isFolder": false
    }
  ]
}
```

Note the key is singular **`file`** (not `files`), and `isFolder` is capital-F
on the wire.

## 3. Large offers → big-message pointer

When the payload is big, the sender does **not** inline the file list. It sends
a pointer and the peer fetches the real body over HTTP:

```json
{ "isMessageSend": "true",
  "messageId": "c0838289d13d4a40b89aaae7df904efe",
  "taskId": "1869b34a-67aa-4dbd-9c77-7074234d8901" }
```

Then: `GET /bigmessage?taskId=<taskId>&messageId=<messageId>`. (`isMessageSend`
is the string `"true"`, not a boolean.)

## 4. Pulling the bytes

```
GET https://192.168.1.156:49371/download?taskId=1212457654&fileId=e9dfc6b2-516a-4930-8764-9cddb8e1bc3e
GET https://192.168.1.156:56392/thumbnail?taskId=1283167697
GET https://192.168.1.156:52986/bigmessage?taskId=305458560&messageId=plVJdBiiNZdOCGnm
```

Host = the sender's IP; port = its negotiated HTTP port; `taskId` + `fileId`
identify the file from the offer.

## 5. Status

```
ack:0:status?{"taskId":"1005444519"}
```

`type` codes: `1` success, `2` failure, `3` cancel, `4` timeout, `100`
file-cancel, `101` file-success — with a human `reason` string when relevant
(`"user interrupt"`, `"no enough space"`, `"timeout"`, …).

## Identity seen

* `senderId`: `A1B2C3D4E5F6i1Tx`  ·  `senderName`: `MYPHONE` (the phone)
* device `protocolVersion`: `4`

## What the log does NOT contain

The low-level **BLE / Wi-Fi-Direct pairing and the UKey2 handshake** — that runs
in the native `pantaConnSDKDll.dll` / `datatrans.dll` daemon, which logs
elsewhere (or not at all). In this capture the two devices were already on the
same LAN, so no Wi-Fi credentials (`ssid` / `psk` / `freq`) were exchanged —
those JSON fields exist in the SDK but weren't used here. The transfer layer
above is fully specified; the first-contact/pairing step is the remaining gap.
