# Crypto

What protects the link between Olink and the phone, layer by layer. The exact
wire formats are in [SCP.md](SCP.md) (pairing and the secure channel) and
[CAST.md](CAST.md) (the phone screen); this page is the overview and where it
came from.

Olink implements all of it natively in Rust on standard libraries:
`aws-lc-rs` for P-256 ECDH, and the RustCrypto `aes-gcm`, `hkdf`, `hmac` and
`sha2` crates. Nothing is home-made: every primitive is a stock one.

## Three layers

| Layer | Where | Key comes from | Protection |
|---|---|---|---|
| Pairing and secure channel | SCP, TCP 10152 | UKey2 key exchange (ECDH P-256) | AES-256-GCM |
| Data channel | TCP 46888 | The KSC, a 16-byte key the phone generates during pairing | HMAC-SHA512 proof, then AES-128-GCM with a fresh key per message |
| Phone-screen signalling | ODMF, TCP 46892 | Its own ECDH P-256 exchange | AES-256-GCM |

## 1. Pairing: UKey2 over SCP

After scanning the QR the phone connects to TCP 10152 and runs **Google's UKey2**
with cipher **P256_SHA512**, exactly as Google publishes it
([github.com/google/ukey2](https://github.com/google/ukey2)), plus one OPPO
addition:

- ECDH on **NIST P-256**; the ClientInit commits to ClientFinished with
  **SHA-512**.
- `derived = SHA-256(Z)`; keys come from **HKDF-SHA256** with the stock salts
  **`UKEY2 v1 auth`** (the verification string) and **`UKEY2 v1 next`** (the
  next-protocol secret), then the D2D client and server keys.
- **OPPO's addition:** `ClientFinished` carries a 16-byte random `ivSpec`.
- From then on every SCP packet is **AES-256-GCM** in both directions, keyed
  with the D2D *client* key, IV = the first 12 bytes of `ivSpec`.

(`next_protocol` is the string `"AES_256_CBC-HMAC_SHA256"`, as in stock UKey2,
but that's only a label: the session cipher actually used is AES-256-GCM.)

Inside that encrypted channel the phone sends `SYNC_SECURE` with the **KSC**:
a 16-byte key it generates. Olink keeps it, but only after you press **Allow**
(see below). The KSC is what the phone uses from then on, including every time
it reconnects.

## 2. The data channel: the KSC

The phone then opens TCP 46888. Before anything else, both sides prove they
hold the KSC:

- The phone sends a challenge `qc` and a timestamp; Olink checks
  `HMAC-SHA512(KSC, qc ‖ timestamp)[..8]` and answers with its own challenge
  `qs` and MAC; the phone confirms.
- Each message after that is **AES-128-GCM** under a key made for it alone:
  `HMAC-SHA512(KSC, qc‖qs ‖ counter)` gives 64 bytes, of which bytes 0–15 are
  the key, 16–27 the nonce and 28–47 the associated data.
- The counter travels with each message and must strictly increase, so
  replayed or reordered messages are refused.

## 3. The phone screen: ODMF signalling

To cast, Olink publishes an `odmf_auth_info` with a fresh P-256 public key
(over the already-encrypted data channel); the phone answers with its own key,
an IV and its encrypted credential. ECDH gives a shared secret for
**AES-256-GCM**. The video itself is WebRTC (DTLS-SRTP), see CAST.md.

## What the crypto does and doesn't do

The pairing QR carries **no secret**: just this PC's address. So anyone on the
same network could start the pairing handshake. What makes a pairing
legitimate is you scanning the code right then, which is why Olink always asks
"Allow this phone?" before it saves a new phone's key (`approval.rs`: one
request at a time, rate-limited, nothing saved without **Allow**). After that,
the keys above protect every byte. PROGRESS.md has the full security review.

## How this was worked out

Two sources, the second correcting the first:

1. **The Windows app's binaries.** `pantaConnSDKDll.dll` exports
   `cryptoUkey2DoKeyAgreement`, `cryptoUkey2Hkdf`, `cryptoGenSalt` and
   `cryptoAesGcmNoPaddingEn/De`, and imports OpenSSL 1.1's P-256
   (`EC_KEY_new_by_curve_name` is always called with NID 415, `prime256v1`),
   HMAC, SHA-256/512 and `EVP_aes_128_gcm`. `pantaChannelService.exe` contains
   the UKey2 protobuf types, `generateP256SHA512ClientFinished`, the literal
   salts `UKEY2 v1 auth` / `UKEY2 v1 next`, and a build path showing it
   vendors Google's code (`utils\ukey2\protobuf_cpp\securemessage.pb.cc`).
   Its logs show an 8-byte value both sides compare on reconnect: that's the
   HMAC-SHA512 KSC proof of section 2.
2. **The phone's own code** (decompiled), checked against live traffic, which
   pinned the transport (Wi-Fi, SCP on 10152), the `ivSpec` addition and the
   real session ciphers.

An earlier version of this page, written from the Windows side alone, guessed
that pairing ran over Bluetooth, that the session used AES-CBC with HMAC, and
that the 8-byte value was the UKey2 verification string. All three were wrong
and are corrected above; PAIRING.md keeps the research log in order.
