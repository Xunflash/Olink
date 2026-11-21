# O+ Connect pairing crypto — the complete spec

Recovered by static analysis of the shipped binaries in `C:\Program Files\O+Connect\daemon`:
`pantaConnSDKDll.dll` (the crypto/ONet library) and `pantaChannelService.exe`
(the pairing policy + handshake driver). Method: PE import/export tables,
`strings`, and targeted `objdump` disassembly. **No decompiler was needed** — the
decisive finding is that the handshake is a *standard, open-source protocol*.

## TL;DR — it's Google UKey2 + SecureMessage, vendored verbatim

The "trust this PC?" pairing is **Google's UKey2** authenticated key exchange
followed by a **Google SecureMessage** D2D secure channel. Both are open-source
(`github.com/google/ukey2`), Apache-2.0. A leaked build path in the binary even
names the vendored copy:

```
F:\ai-windows\PC_PantaConnect\utils\ukey2\protobuf_cpp\securemessage.pb.cc
```

The protobuf message types are the stock UKey2 ones, confirmed in the binary:
`securegcm.Ukey2ClientInit.CipherCommitment`, `securegcm.Ukey2Message.Type`,
`securegcm.Ukey2Alert.AlertType`, `securemessage.EcP256PublicKey`,
`securemessage.Header`, `securemessage.SigScheme`, `securemessage.EncScheme`.

**Consequence for the Linux client: you don't reverse or reimplement the pairing
crypto. You link the published `google/ukey2` + SecureMessage libraries and drive
them.** The hard part is solved upstream.

## The primitives (CAPTURE-VERIFIED from the binaries)

| Role | Primitive | Evidence |
|---|---|---|
| Handshake | **UKey2, cipher `P256_SHA512`** | `generateP256SHA512ClientFinished`; `Ukey2ClientInit.CipherCommitment` |
| Key agreement | **ECDH on NIST P-256** | `EC_KEY_new_by_curve_name(ecx=0x19f)` = NID 415 = `prime256v1`, at every call site; `EVP_PKEY_derive` → 32-byte shared secret |
| Commitment hash | **SHA-512** | the `P256_SHA512` cipher name; `EVP_sha512` imported |
| KDF | **HKDF-SHA256 (RFC 5869)** | `cryptoUkey2Hkdf`: HMAC extract+expand, `EVP_PKEY_new_mac_key(0x357=EVP_PKEY_HMAC)` + `EVP_sha256` + `EVP_DigestSign*`, single `0x01` counter byte, 32-byte PRK |
| HKDF salts | **`UKEY2 v1 auth`**, **`UKEY2 v1 next`** | literal strings in `pantaChannelService.exe` (the stock UKey2 constants) |
| D2D session AEAD | **SecureMessage `AES_256_CBC` + `HMAC_SHA256`** (encrypt-then-MAC) | `AES_256_CBC-HMAC_SHA256`, `securemessage.EncScheme`/`SigScheme` |
| D2D signatures | **`ECDSA_P256_SHA256`** | string `ECDSA_P256_SHA256`; `EVP_PKEY_sign`/`EVP_PKEY_verify` |
| WiFi transfer channel | **AES-128-GCM** | `cryptoAesGcmNoPaddingEn/De`, `EVP_aes_128_gcm`; the `decryptAesGcm` seen in the ONet auth logs |
| RNG / salt | `RAND_bytes` | `cryptoGenSalt` |

Crypto is **OpenSSL 1.1** (`libcrypto-1_1-x64.dll`) throughout.

### `pantaConnSDKDll.dll` — the exported crypto API (generic, reusable)

```
cryptoGetEcdhKeyPair        cryptoGetEcdhSharedKey      cryptoUkey2DoKeyAgreement
cryptoUkey2Hkdf             cryptoGenSalt
cryptoAesGcmNoPaddingEn/De  cryptoAesCbcNoPaddingEn/De  cryptoAesCtr…  cryptoAesEcb…
```

These take salt/info/IV/tag **as parameters** — the DLL is a neutral crypto
toolbox. The UKey2 *policy* (which labels, which cipher, the transcript) lives in
`pantaChannelService.exe`, which is why the labels above are there and not in the DLL.

## The handshake, end to end

```
LAYER 1 — Bluetooth, module `fastPair` + `pantaChannelService`
  • BLE GATT service UUID 0xAA16 / 0xAA17 (0000aa16/aa17-0000-1000-8000-00805f9b34fb),
    advertised via WinRT (StartAdvertisementInternal) alongside Wi-Fi Direct.
  • UKey2 handshake over GATT:
       ClientInit  (cipher_commitments: P256_SHA512, SHA-512 commitment of ClientFinished)
       ServerInit  (EcP256PublicKey)
       ClientFinished (EcP256PublicKey)      ← generateP256SHA512ClientFinished
    → ECDH P-256 → shared secret Z (32 B)
  • UKey2 derives, via HKDF-SHA256:
       auth string   = HKDF(Z-derived secret, salt=SHA256("UKEY2 v1 auth"), …)   → the 8-byte RC
       next secret   = HKDF(…,               salt=SHA256("UKEY2 v1 next"), …)    → D2D key seed
  • The "Allow this device?" dialog authorises the exchange (the confirm).
  • SecureMessage D2DConnectionContext is created: AES-256-CBC + HMAC-SHA256.
  • Result key (KSC) persisted: keyMgrSaveKsc + keyMgrSavePeerDeviceId → silent reconnects.
  ───────────────────────────────────────────────────────────────────
LAYER 2 — Wi-Fi/ONet, module `authentication`   (re-proof on each connect)
  • getKsc loads the persisted key; generate{Server,Client}ChallengeMac;
    checkRemoteParams compares the 8-byte RC; checkRc2 → auth success.
  • Bulk traffic then uses AES-128-GCM (cryptoAesGcm*) — the transfer protocol in PROTOCOL.md.
```

The 8-byte RC captured on two sessions (`f6 7b ce 14 40 96 8e 06`,
`53 28 0a 12 cf 05 27 48`) is the **UKey2 verification/auth string truncated to 8
bytes** — exactly what `GetVerificationString()` produces in upstream UKey2.

## What a Linux client actually has to build

Crypto: **none from scratch.** Use `google/ukey2` (C++, with SecureMessage) or a
port. Everything above is its default behaviour with cipher `P256_SHA512`.

OPPO-specific glue (the real work):
1. **BLE**: advertise/connect the GATT service **0xAA16/0xAA17**, and carry the
   UKey2 `Ukey2Message` frames over its characteristics. (BlueZ on Linux.)
2. **Confirm UX**: show an "Allow" dialog; UKey2's verification string is the hook.
3. **Persist** the resulting D2D key + peer device-id (mirror `keyMgrSaveKsc`).
4. **Wi-Fi/ONet layer**: the `authentication` re-proof (RC from the stored key)
   and then the AES-128-GCM transfer channel (already mapped in PROTOCOL.md).

Item 1 (the GATT framing of UKey2) is the one piece still worth a BLE sniff to
confirm characteristic layout; the crypto itself is done.

## Binaries referenced

- `daemon/pantaConnSDKDll.dll` — OpenSSL-based crypto + ONet (sha256 `671825e2…`).
- `daemon/pantaChannelService.exe` — UKey2/SecureMessage pairing driver, the
  `authentication` module (generateServerChallengeMac, checkRemoteParams, getKsc).
- `daemon/libcrypto-1_1-x64.dll` — OpenSSL 1.1.
