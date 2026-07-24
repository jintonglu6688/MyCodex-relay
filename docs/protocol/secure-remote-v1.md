# Secure Remote Protocol v1

This document is the Relay-owned byte contract for secure remote protocol
version 1. The normative known-answer vector is
[`test-vectors/secure-remote-v1.json`](test-vectors/secure-remote-v1.json).
Windows, Relay, and Android must reject any protocol version other than `1`;
version 1 has no algorithm negotiation or downgrade path.

## Fixed algorithms

- ECDSA P-256 with SHA-256.
- ECDH P-256.
- HKDF-SHA-256 and HMAC-SHA-256.
- AES-256-GCM with a 12-byte nonce and 16-byte authentication tag.
- SHA-256.
- Unpadded Base64Url for binary values carried as text.
- P-256 public keys as 65-byte uncompressed SEC1 values:
  `0x04 || X[32] || Y[32]`.
- ECDSA signatures as 64-byte `R[32] || S[32]`, both unsigned big-endian.
  DER signatures are not part of this protocol.

The vector signatures use RFC 6979 deterministic nonces and low-S
normalization so the known answers are reproducible. Production signatures do
not need deterministic nonces, but must use a cryptographically secure signer
and the same 64-byte wire format.

## Canonical encoding

Transcripts are byte strings, never serialized JSON. The notation below is:

- `S(value)`: UTF-8 bytes encoded as `U32BE(length) || value`.
- `B(value)`: bytes encoded as `U32BE(length) || value`.
- `I64(value)`: signed two's-complement 8-byte big-endian integer.
- `U64(value)`: unsigned 8-byte big-endian integer.

Every domain label is encoded with `S`. Every string and byte-array field is
length-prefixed, including fixed-size public keys, hashes, nonces and
signatures. An absent optional byte field is `B(empty)`, not an omitted field.
Protocol versions, key versions, binding versions, ciphertext lengths and Unix
millisecond timestamps use `I64`. Envelope sequence numbers use `U64`. UUIDs
are lowercase canonical ASCII strings encoded with `S`.

`AppendField`, `AppendString`, and `AppendInt64` in
`internal/protocol/canonical.go` are the Relay reference primitives.

## Transcript layouts

Fields are appended in the exact order shown.

### Pairing package

Domain: `MYCODEX-PAIRING-PACKAGE-V1`

1. `S(domain)`
2. `I64(protocolVersion)`
3. `S(relayUrl)`
4. `B(relaySigningPublicKey)`
5. `B(relaySigningKeyFingerprint)`
6. `B(embeddedTlsCertificateSha256)`; empty for external Relay
7. `S(tenantId)`
8. `S(hostId)`
9. `S(hostName)`
10. `S(inviteId)`
11. `B(inviteSecret)`
12. `I64(expiresAt)`
13. `B(hostSigningPublicKey)`
14. `B(hostAgreementPublicKey)`
15. `I64(hostKeyVersion)`

`hostSignature` is the host ECDSA signature of this transcript.

### Visible pairing-claim header

Domain: `MYCODEX-PAIRING-CLAIM-V1`

1. `S(domain)`
2. `I64(protocolVersion)`
3. `S(inviteId)`
4. `S(tenantId)`
5. `S(hostId)`
6. `S(claimId)`
7. `S(deviceId)`
8. `B(deviceAgreementPublicKey)`
9. `I64(deviceKeyVersion)`
10. `B(clientNonce)`
11. `I64(ciphertextLength)`, including the 16-byte GCM tag

The 12-byte claim encryption nonce is transported beside this header. The
canonical header is the claim AES-GCM AAD.

### Pairing claim

Domain: `MYCODEX-PAIRING-CLAIM-V1`

The transcript without proof or signature is:

1. `S(domain)`
2. `I64(protocolVersion)`
3. `S(claimId)`
4. `S(inviteId)`
5. `S(tenantId)`
6. `S(hostId)`
7. `S(deviceId)`
8. `S(deviceName)`
9. `S(platform)`
10. `S(appVersion)`
11. `B(deviceSigningPublicKey)`
12. `B(deviceAgreementPublicKey)`
13. `I64(deviceKeyVersion)`
14. `B(clientNonce)`
15. `I64(createdAt)`

The invite proof and signed/plaintext forms are:

```text
inviteProof = HMAC-SHA-256(inviteSecret, claimWithoutProof)
claimForSignature = claimWithoutProof || B(inviteProof)
deviceSignature = ECDSA-device-signing(claimForSignature)
claimPlaintext = claimForSignature || B(deviceSignature)
```

The outer and inner routing values must match exactly after decryption.

### Pairing approval

Domain: `MYCODEX-PAIRING-APPROVAL-V1`

The approval binding transcript is:

1. `S(domain)`
2. `I64(protocolVersion)`
3. `S(bindingId)`
4. `S(tenantId)`
5. `S(hostId)`
6. `S(deviceId)`
7. `B(hostSigningPublicKey)`
8. `B(hostAgreementPublicKey)`
9. `I64(hostKeyVersion)`
10. `B(deviceSigningPublicKey)`
11. `B(deviceAgreementPublicKey)`
12. `I64(deviceKeyVersion)`
13. `B(relaySigningPublicKey)`
14. `B(relaySigningKeyFingerprint)`
15. `I64(approvedAt)`
16. `I64(bindingVersion)`

```text
hostApprovalSignature = ECDSA-host-signing(approvalTranscript)
approvalPlaintext = approvalTranscript || B(hostApprovalSignature)
```

The approval header, which is also the approval AES-GCM AAD, is:

1. `S(domain)`
2. `I64(protocolVersion)`
3. `S(claimId)`
4. `S(inviteId)`
5. `S(tenantId)`
6. `S(hostId)`
7. `S(deviceId)`
8. `S(status)`
9. `I64(bindingVersion)`
10. `B(approvalNonce)`
11. `I64(ciphertextLength)`, including the 16-byte GCM tag

### Relay challenge and proof

Challenge domain: `MYCODEX-RELAY-CHALLENGE-V1`

1. `S(domain)`
2. `I64(protocolVersion)`
3. `B(relaySigningKeyFingerprint)`
4. `S(challengeId)`
5. `B(challengeValue)`
6. `S(subjectType)`
7. `S(subjectId)`
8. `S(targetType)`
9. `S(targetId)`
10. `S(purpose)`
11. `I64(issuedAt)`
12. `I64(expiresAt)`

`relaySignature` is the Relay ECDSA signature of the challenge transcript.

Proof domain: `MYCODEX-RELAY-PROOF-V1`

1. `S(domain)`
2. `I64(protocolVersion)`
3. `B(challengeTranscript)`
4. `B(relaySignature)`
5. `S(subjectType)`
6. `S(subjectId)`

The subject signs the proof transcript with its registered long-term signing
key.

### Session Hello

Domain: `MYCODEX-SESSION-HELLO-V1`

The client Hello transcript is:

1. `S(domain)`
2. `I64(protocolVersion)`
3. `S(tenantId)`
4. `S(hostId)`
5. `S(deviceId)`
6. `S(bindingId)`
7. `I64(bindingVersion)`
8. `I64(deviceKeyVersion)`
9. `B(clientEphemeralPublicKey)`
10. `B(clientNonce)`
11. `I64(clientCreatedAt)`

The device signs this transcript. The server Hello transcript is then:

```text
clientHelloTranscript
|| B(clientSignature)
|| I64(hostKeyVersion)
|| B(serverEphemeralPublicKey)
|| B(serverNonce)
|| I64(serverCreatedAt)
```

The host signs the server Hello transcript. The complete session transcript is:

```text
sessionComplete = serverHelloTranscript || B(serverSignature)
```

### Session confirmation

Domain: `MYCODEX-SESSION-CONFIRM-V1`

1. `S(domain)`
2. `B(sessionComplete)`
3. `S(senderRole)`, exactly `android` or `windows`

The confirmation value is HMAC-SHA-256 of this transcript using the session
confirmation key.

### Encrypted envelope AAD

Domain: `MYCODEX-ENVELOPE-AAD-V1`

1. `S(domain)`
2. `I64(protocolVersion)`
3. `S(sessionId)`
4. `S(tenantId)`
5. `S(hostId)`
6. `S(deviceId)`
7. `S(senderRole)`
8. `S(messageType)`
9. `S(messageId)`
10. `U64(sequence)`
11. `I64(createdAt)`
12. `S(payloadEncoding)`, exactly `encrypted-json`
13. `B(nonce)`
14. `I64(ciphertextLength)`, including the 16-byte GCM tag

## Key derivation and encryption

HKDF below means RFC 5869 HKDF-SHA-256. `empty salt` means a zero-length salt,
which RFC 5869 treats as a HashLen-sized all-zero salt. Labels are raw UTF-8
HKDF info bytes with no canonical length prefix.

Pairing:

```text
pairingSharedSecret = P256-ECDH(deviceAgreementPrivateKey, hostAgreementPublicKey)
pairingSalt = SHA-256(inviteSecret)
pairingInfo = SHA-256(
    pairingPackageTranscript
    || B(hostSignature)
    || visibleClaimHeader
)
pairingBaseKey = HKDF(pairingSharedSecret, pairingSalt, pairingInfo, 32)
claimKey = HKDF(pairingBaseKey, empty salt, "claim encryption", 32)
approvalKey = HKDF(pairingBaseKey, empty salt, "approval encryption", 32)
```

The claim and approval plaintexts use AES-256-GCM with their respective keys,
12-byte fixed vector nonces and canonical headers as AAD.

Pairing code:

```text
pairingCodeTranscript =
    S("MYCODEX-PAIRING-CODE-V1") || B(claimPlaintext)
digest = SHA-256(pairingCodeTranscript)
code = U32BE(digest[0:4]) mod 1000000
display = six decimal digits, left padded with zeroes
```

Session:

```text
sessionSharedSecret = P256-ECDH(clientEphemeralPrivateKey, serverEphemeralPublicKey)
sessionSalt = SHA-256(clientNonce || serverNonce)
sessionMaster = HKDF(sessionSharedSecret, sessionSalt, sessionComplete, 32)
androidToWindowsKey = HKDF(sessionMaster, empty salt, "android to windows key", 32)
windowsToAndroidKey = HKDF(sessionMaster, empty salt, "windows to android key", 32)
androidToWindowsNoncePrefix =
    HKDF(sessionMaster, empty salt, "android to windows nonce prefix", 4)
windowsToAndroidNoncePrefix =
    HKDF(sessionMaster, empty salt, "windows to android nonce prefix", 4)
confirmationKey = HKDF(sessionMaster, empty salt, "session confirmation", 32)
```

An envelope nonce is `directionNoncePrefix[4] || U64(sequence)`. Sequence
numbers start at 1, never repeat, and are scoped to one direction of one
session.

## Canonical vector

The JSON vector contains no generated time, machine path or random value.
Private scalars are the fixed integers 1 through 6, the invite secret is the
32-byte range `00` through `1f`, IDs are fixed lowercase UUIDs, and all nonces
and Unix millisecond times are fixed.

For the vector only, scalar 5 supplies both the device long-term agreement key
and the client-side session ECDH input so the required scalar set remains
exactly 1 through 6. Production sessions must generate a fresh client and
server ephemeral P-256 key pair for every connection and must never reuse a
long-term agreement private key as an ephemeral key.

`internal/protocol/canonical_test.go` regenerates every public key, transcript,
signature, HMAC, ECDH result, HKDF result, AES-GCM ciphertext, pairing code and
envelope value and compares them byte-for-byte with the checked-in JSON.

## Relay signing identity

Relay uses a distinct ECDSA P-256 signing key stored as PKCS#8 at:

```text
Config.StatePath + ".identity.pk8"
```

Creation writes a mode `0600` temporary file in the same directory, syncs and
closes it, then atomically renames it to the target path. The published Relay
fingerprint is:

```text
Base64Url-no-padding(SHA-256(uncompressed-SEC1-public-key))
```

Relay identity files, private keys, full pairing URIs, invite secrets, access
tokens, shared secrets, session keys and plaintext business payloads must never
be logged.
