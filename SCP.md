# SCP — the O+ Connect pairing/secure-channel protocol (Wi-Fi path)

Recovered 2026-11-19 from the phone's own code (`com.heytap.accessory`,
`/product/priv-app/AccessoryFramework/AccessoryFramework.apk` on a Find X9 Ultra,
decompiled with jadx) and verified against a live capture (see PAIRING.md).
Class names below are the phone's (`com.oplus.pantaconnect.*`); obfuscated
single-letter names are given as `file.java` under `pair/scp/` or `connection/scp/`.

**This replaces the BLE-GATT assumption for first contact.** After a QR scan the
phone (SCP *client*, "Seeker") opens **TCP to the PC on port 10152** and runs SCP;
the PC is the SCP *server* (`RealScpServer`, `pair/scp/e.java`).

## 1. Framing (`ScpPacket`, serializer `mm/c.java h0`)

Every packet = 12-byte main header (+ optional fragment headers) + payload.

| Byte | Bits | Field |
|---|---|---|
| 0 | hi nibble | `version` (`ScpVersion` V3=3, **V4=4**) |
| 0 | lo nibble | `serviceType` (SYSTEM_SERVICE=0, APPLICATION_SERVICE=1) |
| 1 | hi nibble | `payloadType` (RAW=0, TEXT=1, JSON=2, **PROTOBUF=3**) |
| 1 | bit 3 | `isPayloadEncrypted` |
| 1 | bit 2 | `isServer` |
| 1 | bits 0-1 | `structType` (SCP_PROTOCOL=0, BUSINESS=1) |
| 2-3 | u16 BE | `payloadLength` |
| 4 | | `nextHeader` (END=0, FRAGMENT=1) |
| 5 | | flags: bit1 `isHello`, bit0 `isCrcEnable` |
| 6-7 | u16 BE | `crc` (0 when disabled) |
| 8-11 | | `agentAddress` = last 4 bytes of SHA-256(namespace + channel) |

Fragment header (if `nextHeader`=1): `next(1) len(1)=6 0 (num<<1|more)(1) 0 id(4?)`.
Not seen yet for small packets.

Observed phone HELLO header: `40 30 0036 00 02 0000 7b08ad12`.
Check: SHA-256("com.heytap.accessory" + "active_connection")[-4:] should be `7b08ad12`.

## 2. Packet payload (`p0`)

```proto
message ScpPacket   { int32 msgType = 1; bytes data = 2; }
enum ScpMessageType { HELLO=0; SYNC=1; SYNC_SECURE=2; UKEY2_INIT=3;
                      UKEY2_FINISHED=4; OOBKEY_BUILD=5; OOBKEY_PROCESS=6;
                      OOBKEY_FINISHED=7; DISCONNECT=65535; }
message Hello       { int32 sequenceNo=1; string channel=2; string namespace=3; string serviceName=4; }   // s
message Sync        { string deviceName=1; int32 keyType=2; bytes customData=3; int32 deviceType=4;
                      int32 activeTriggerMode=5; string modelId=6; int32 linkType=7; }                   // j0
message SyncSecure  { string deviceId=1; bytes ksc=2; bytes kscAlias=3; }                                 // m0
message Disconnect  { int32 sequenceNo=1; int32 disconnectCode=2; string disconnectReason=3; }            // l
enum ScpKeyType     { EMPTY=0; UKEY2=1; OOBKEY=2; BOTH=3; }
```

When a session key exists, `ScpPacket` bytes are AES-GCM-encrypted and header
bit `isPayloadEncrypted` is set (`RealScpProtocol.l`, `pair/scp/d.java`).

## 3. Server state machine (`RealScpServer.handshakeInternal`, `pair/scp/e.java`)

Each read has a **5 s timeout** (else the peer sends DISCONNECT 2514).

1. READ_HELLO — client HELLO `{seq=random, channel, namespace}` (header isHello=1).
2. WRITE_HELLO — server HELLO `{seq = client seq + 1, same channel, namespace}`,
   header isHello=1, isServer=1. Version = min(peer, 4).
3. READ_SYNC — client Sync (keyType etc.).
4. WRITE_SYNC — server Sync `{deviceName, keyType, customData, deviceType,
   activeTriggerMode, modelId (3 bytes, default "2B1488"), linkType}`.
5. Key-type negotiation → UKEY2 (falls back to UKEY2 on mismatch if activeTriggerMode≠0).
6. **UKey2** (`ScpUKey2`, `pair/scp/m.java`), server side:
   - wait `UKEY2_INIT` carrying the client's Ukey2Message(ClientInit)
   - send `UKEY2_INIT` carrying Ukey2Message(ServerInit)
   - wait `UKEY2_FINISHED` carrying Ukey2Message(ClientFinished)
   - send `UKEY2_FINISHED` with **empty** data (ack)
7. READ_SYNC_SECURE (encrypted) — client `{deviceId, ksc, kscAlias}`.
8. WRITE_SYNC_SECURE (encrypted) — server `{own deviceId, same ksc, same kscAlias}`.
   The phone generates the KSC; the PC stores it (`persistKscAfterUserConfirm`).

## 4. UKey2 — stock Google UKey2 P256_SHA512, with one OPPO addition

Vendored `com.google.security.cryptauth.lib.securegcm.Ukey2Handshake` (`a.java`),
protos in package `h2`:

```proto
message Ukey2Message   { int32 message_type=1; bytes message_data=2; }  // ALERT=1 CLIENT_INIT=2 SERVER_INIT=3 CLIENT_FINISH=4
message Ukey2ClientInit{ int32 version=1; bytes random=2; repeated CipherCommitment cipher_commitments=3; string next_protocol=4; }
message CipherCommitment { int32 handshake_cipher=1; bytes commitment=2; }   // P256_SHA512 = 100
message Ukey2ServerInit{ int32 version=1; bytes random=2; int32 handshake_cipher=3; bytes public_key=4; }
message Ukey2ClientFinished { bytes public_key=1; bytes ivSpec=2; }   // <-- ivSpec: OPPO addition, 16 random bytes
```

- `next_protocol` must be `"AES_256_CBC-HMAC_SHA256"`.
- Commitment = SHA-512(serialized Ukey2Message(CLIENT_FINISH)).
- Public keys: securemessage `GenericPublicKey{type=1(EC_P256), ec_p256_public_key=2{x=1,y=2}}`.
- ECDH P-256 → Z; `derived = SHA-256(Z)` (stock); transcript = ClientInit msg ‖ ServerInit msg.
- auth = HKDF-SHA256(derived, salt="UKEY2 v1 auth", info=transcript) (verification string)
- next = HKDF-SHA256(derived, salt="UKEY2 v1 next", info=transcript, 32)
- D2D: clientKey = HKDF(next, salt=SHA-256("D2D"), info="client"); serverKey = …"server".

## 5. Session cipher after UKey2 (`tf/e.java e`, `vk/b.java`, `uk/b.java`)

**Both directions use AES-256-GCM with key = clientKey** (server takes `h2.a.f19273b`,
client takes `h2.a.f19272a`, both = the "client" D2D key) and a **fixed IV =
first 12 bytes of the client's `ivSpec`**, 128-bit tag. Encrypted = the serialized
`ScpPacket` bytes.
