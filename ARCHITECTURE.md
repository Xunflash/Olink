# Architecture — a direct Linux ⇄ phone client, no helper app

The goal: the **Linux machine itself** plays the "PC" role that O+ Connect on the
phone already knows how to talk to. No OPPO daemon, no bridge process — our app
advertises over BLE, runs the pairing handshake, persists the trust, and then
speaks the Wi-Fi transfer protocol directly. Everything below is organised around
making that one path work end to end.

## The connection pipeline

The phone drives the same five stages whether the peer is a Windows PC or us. The
architecture gives each stage one module and one clean seam, so they can be built
and tested independently:

```
   phone                         Linux app (this project)
   ─────                         ────────────────────────
                                 ┌──────────── app::ConnectionManager ───────────┐
                                 │   orchestrates the lifecycle below            │
                                 └───────────────────────────────────────────────┘
   scan BLE/LAN  ───────────▶   discovery   advertise GATT 0xAA16/0xAA17 (ble),
                                            ONet UDP :46888 + mDNS (discovery)
   "trust this PC?"  ◀───────▶   pairing     UKey2 (P256_SHA512) over a
                                 + ble       MessageTransport = the BLE GATT link
                                 + trust      → derive D2D keys → persist TrustRecord
   reconnect (silent) ◀──────▶   session     Wi-Fi re-proof using the stored key
                                            (the `authentication` re-proof), opens
                                            the AES-GCM channel
   send/receive files ◀──────▶   protocol    WebSocket control + HTTP file routes
                                            (already recovered, see PROTOCOL.md)
```

## Module map

```
src-tauri/src/
  main.rs            Tauri entry; builds AppState and the ConnectionManager.
  app/               ORCHESTRATION
    mod.rs             ConnectionManager — sequences the pipeline.
    lifecycle.rs       Lifecycle state machine (the states the UI reflects).
  transport.rs       THE SEAM: MessageTransport — framed bytes in/out. UKey2 runs
                     over the BLE impl; the session runs over the Wi-Fi impl.
  ble/               BLE (BlueZ)
    mod.rs             BlePeripheral — advertises 0xAA16/0xAA17, exposes the GATT
                       characteristics as a MessageTransport for pairing.
  pairing/           TRUST ESTABLISHMENT
    mod.rs             QR `oconn`, the two-layer model, account-match (reference).
    ukey2.rs           Ukey2Pairing — the handshake driver over a MessageTransport.
  trust/             KEY PERSISTENCE
    mod.rs             TrustStore + TrustRecord — mirrors keyMgrSaveKsc /
                       keyMgrSavePeerDeviceId so reconnects are silent.
  discovery/         FINDABILITY
    mod.rs             Discovery trait; BLE scan + ONet/mDNS backends.
  session/           AUTHENTICATED CONNECTION
    mod.rs             Session — the Wi-Fi re-proof + crypto context that bridges a
                       TrustRecord to the transfer protocol.
  protocol/          TRANSFER (recovered in full)
    messages.rs  websocket.rs  http_files.rs  tls.rs
  commands.rs        Tauri commands the UI calls.
  state.rs           Shared state (registry, peers, trust store, manager).
```

## The one seam that makes it compose: `MessageTransport`

UKey2 doesn't care whether its frames travel over BLE GATT or a socket — it just
needs "send this message, receive the next." We express that as one trait
(`transport::MessageTransport`). Two implementations:

* `ble::BlePeripheral` — carries UKey2 frames over the GATT characteristics during
  **pairing** (Layer 1).
* `session` uses a socket transport for the **Wi-Fi re-proof and transfer** (Layer 2).

Because pairing is written against the trait, not against BlueZ, it can be unit-
tested over an in-memory transport before any radio is involved.

## Data flow for a first-time pair

1. `app::ConnectionManager::start()` → `ble::BlePeripheral::advertise()` publishes
   service `0xAA16/0xAA17`; `discovery` starts ONet/mDNS.
2. Phone connects over BLE and begins UKey2. The GATT characteristic read/writes
   are handed to `pairing::ukey2::Ukey2Pairing` as a `MessageTransport`.
3. UKey2 (cipher `P256_SHA512`) completes → a `D2DContext` (the derived keys).
   The user's "Allow" authorises it.
4. `trust::TrustStore::put()` persists a `TrustRecord { peer_id, ksc, … }`.
5. On the next connect the phone comes in over Wi-Fi; `session::Session::resume()`
   loads the `TrustRecord`, runs the re-proof, and opens the AES-GCM channel.
6. `protocol` carries the actual files over that channel.

## Crypto ownership

No crypto is reimplemented. `pairing::ukey2` wraps the published `google/ukey2`
(cipher `P256_SHA512`, HKDF-SHA256 salts `UKEY2 v1 auth` / `UKEY2 v1 next`,
SecureMessage AES-256-CBC + HMAC-SHA256). `session` owns the Wi-Fi AES-128-GCM
context. See CRYPTO.md for the full spec and the evidence behind every choice.

## Status honesty

`commands::layer_status` reports each layer as `ready` / `scaffold` / `needs-capture`
so the UI never overstates completeness. Today: protocol is `ready`; the crypto
*design* is `ready` (UKey2); BLE, UKey2 wiring, trust, session and discovery are
`scaffold` — real signatures and data flow, implementations to fill in. The one
remaining *capture* is the BLE GATT characteristic layout for UKey2 frames.
