# START HERE — brief for Claude Code

You (Claude Code) are picking up a project to build a **native Linux client for
O+ Connect**, the OPPO/OnePlus/Realme cross-device transfer app that has no Linux
version. The goal is for the phone to connect **directly to this Linux machine**,
with the machine playing the "PC" role itself — no OPPO helper app, no bridge.

## Read these first, in order

1. `README.md` — the overview and current state.
2. `ARCHITECTURE.md` — the module map, the connection pipeline, the trait seams.
3. `CRYPTO.md` — the pairing crypto spec (it's standard Google UKey2 — do not
   reimplement it, link `github.com/google/ukey2`).
4. `PAIRING.md` and `PROTOCOL.md` — the discovery/trust model and the transfer
   protocol, both recovered from the Windows build.

All the reverse-engineering is **already done and verified against a real device**.
Your job is implementation, not research. Trust these docs.

## Who you're working with (important)

The person running you is **not a programmer** and has no coding background. They
are patient, motivated, and happy to be your hands on the hardware — but they
cannot read code or debug. So:

- Explain what you're doing and why, in plain English, before you do it.
- Make the decisions yourself; don't ask them to choose between technical options
  they can't evaluate. Pick the sensible default and say what you picked.
- When you need them to *do* something physical (plug in the phone, tap a button,
  run a capture command you give them), give exact, copy-pasteable steps and say
  what a success vs failure looks like.
- Keep momentum: small steps, build often, and tell them plainly where things
  stand after each one. Celebrate the milestones — first compile, first BLE
  advertisement, first successful pair.

## The hardware for testing

- This Linux laptop (the dev machine).
- An **OPPO Find X9 Ultra** phone (model CPH2841) running O+ Connect. It is the
  peer to pair and transfer with. Pairing is cross-account and needs **no OPPO
  account** — a signed-out state is fine (see PAIRING.md).
- Bluetooth + Wi-Fi on the same network. The pairing handshake runs over
  Bluetooth LE; the file transfer runs over Wi-Fi.

## Build order (the plan)

Work through these in sequence; each should build and be sanity-checked before
moving on. The status panel in the app (`commands::layer_status`) should be kept
honest as you go.

**0. Dev environment.** Detect the distro and install what's needed yourself:
   Rust (stable, via `rustup`), Node 18+, the Tauri Linux system dependencies
   (webkit2gtk, gtk3, etc.), and the BlueZ development libraries. Get the scaffold
   to compile and the app window to open. Fix any dependency-version drift in
   `Cargo.toml` (it was written without a crate cache).

**1. Protocol smoke test.** The transfer protocol (`protocol/`) is already
   written. Get `cargo test` green and confirm the message codec round-trips.

**2. BLE peripheral** (`ble/mod.rs`). Add the `bluer` crate. Advertise the pairing
   GATT service `0xAA16`/`0xAA17` and accept a connection from the phone. First
   goal: the phone *sees* this machine in O+ Connect's device list.

**3. Capture the GATT layout.** This is the one wire detail not yet pinned. Walk
   the human through running a BLE capture (`sudo btmon` to a file, or Wireshark
   on `bluetooth0`) while they trigger a pair from the phone. Use it to learn
   which characteristic is write-to-peer vs notify-from-peer and the fragmentation
   scheme. Implement `BleTransport` (the `MessageTransport` impl) from what you see.

**4. UKey2 pairing** (`pairing/ukey2.rs`). Link `google/ukey2` (C++ via FFI, or a
   Rust port if a solid one exists), cipher **P256_SHA512**. Drive the handshake
   over the `BleTransport`. Wire the `ConfirmPrompt` to a simple "Allow this
   device?" dialog in the UI. First goal: a completed handshake and a derived key.

**5. Trust store** (`trust/mod.rs`). It's already written (file-backed). Persist
   the pairing so reconnects are silent. Later, move the key into the OS secret
   service.

**6. Session + transfer** (`session/mod.rs` → `protocol/`). Implement the Wi-Fi
   re-proof from the stored key and the AES-128-GCM channel, then connect it to
   the transfer protocol. First goal: **send one file phone→laptop and laptop→phone.**

**7. Polish.** Discovery niceties (so it connects without the QR), the UI, error
   handling, packaging as a `.deb`/AppImage/rpm.

## Working style

- Prefer linking well-known libraries over hand-rolling, especially for crypto.
- Commit after each working step with a clear message, so progress is never lost.
- Don't overstate completeness — keep the status panel accurate.
- If you hit a hardware/protocol wall, the fallback is another capture: have the
  human record the Windows app doing the same thing and compare. The Windows
  install is at `C:\Program Files\O+Connect` if they dual-boot.

## Honest risks

BLE and a reverse-engineered handshake are finicky; step 3–4 is where this could
stall and need extra captures or iteration. Everything up to the crypto is
well-understood, and the crypto itself is a known open standard, so the path is
real — it just needs patient, iterative work against the phone.

Start by reading the docs above, then set up the dev environment (step 0) and
tell the human what you found and what you're going to do first.
