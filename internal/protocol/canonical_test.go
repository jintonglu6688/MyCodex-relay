package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendFieldUsesFourByteBigEndianLength(t *testing.T) {
	got := AppendField([]byte{0xff}, []byte{0xaa, 0xbb})
	want := []byte{0xff, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb}
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendField() = %x, want %x", got, want)
	}
}

func TestSecureRemoteVectorMatchesGeneratedValues(t *testing.T) {
	vector := generateSecureRemoteVector(t)
	want, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}
	want = append(want, '\n')

	path := filepath.Join("..", "..", "docs", "protocol", "test-vectors", "secure-remote-v1.json")
	if os.Getenv("UPDATE_SECURE_REMOTE_VECTOR") == "1" {
		if err := os.WriteFile(path, want, 0644); err != nil {
			t.Fatalf("WriteFile(%q) failed: %v", path, err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) failed: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s does not match generated secure remote v1 values", path)
	}
}

type secureRemoteVector struct {
	ProtocolVersion int            `json:"protocolVersion"`
	Inputs          map[string]any `json:"inputs"`
	PublicKeys      map[string]any `json:"publicKeys"`
	Transcripts     map[string]any `json:"transcripts"`
	Signatures      map[string]any `json:"signatures"`
	Pairing         map[string]any `json:"pairing"`
	Session         map[string]any `json:"session"`
	Envelope        map[string]any `json:"envelope"`
}

func generateSecureRemoteVector(t *testing.T) secureRemoteVector {
	t.Helper()

	const (
		tenantID    = "11111111-1111-1111-1111-111111111111"
		hostID      = "22222222-2222-2222-2222-222222222222"
		deviceID    = "33333333-3333-3333-3333-333333333333"
		inviteID    = "44444444-4444-4444-4444-444444444444"
		claimID     = "55555555-5555-5555-5555-555555555555"
		challengeID = "66666666-6666-6666-6666-666666666666"
		bindingID   = "77777777-7777-7777-7777-777777777777"
		sessionID   = "88888888-8888-8888-8888-888888888888"
		messageID   = "99999999-9999-9999-9999-999999999999"
		relayURL    = "https://relay.example.com"
	)
	const (
		inviteExpiresAt int64 = 1893456600000
		claimCreatedAt  int64 = 1893456001000
		approvedAt      int64 = 1893456002000
		challengeAt     int64 = 1893456003000
		challengeExpiry int64 = 1893456063000
		clientHelloAt   int64 = 1893456004000
		serverHelloAt   int64 = 1893456005000
		messageAt       int64 = 1893456006000
	)

	keys := map[string]*ecdsa.PrivateKey{
		"relaySigning":           vectorPrivateKey(t, 1),
		"hostSigning":            vectorPrivateKey(t, 2),
		"hostAgreement":          vectorPrivateKey(t, 3),
		"deviceSigning":          vectorPrivateKey(t, 4),
		"deviceAgreement":        vectorPrivateKey(t, 5),
		"sessionServerEphemeral": vectorPrivateKey(t, 6),
	}
	public := func(name string) []byte {
		key := keys[name]
		return elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	}

	inviteSecret := vectorBytes(0x00, 32)
	clientNonce := vectorBytes(0x20, 32)
	claimNonce := vectorBytes(0x40, 12)
	approvalNonce := vectorBytes(0x50, 12)
	challengeValue := vectorBytes(0x60, 32)
	sessionClientNonce := vectorBytes(0x80, 32)
	sessionServerNonce := vectorBytes(0xa0, 32)

	relayPublic := public("relaySigning")
	relayFingerprintDigest := sha256.Sum256(relayPublic)
	relayFingerprint := relayFingerprintDigest[:]

	pairingPackageTranscript := vectorTranscript(
		"MYCODEX-PAIRING-PACKAGE-V1",
		int64(1),
		relayURL,
		relayPublic,
		relayFingerprint,
		[]byte{},
		tenantID,
		hostID,
		"Demo Windows Host",
		inviteID,
		inviteSecret,
		inviteExpiresAt,
		public("hostSigning"),
		public("hostAgreement"),
		int64(1),
	)
	hostPackageSignature := vectorSign(t, keys["hostSigning"], pairingPackageTranscript)

	claimTranscriptWithoutProof := vectorTranscript(
		"MYCODEX-PAIRING-CLAIM-V1",
		int64(1),
		claimID,
		inviteID,
		tenantID,
		hostID,
		deviceID,
		"Demo Android Device",
		"android",
		"1.0.0",
		public("deviceSigning"),
		public("deviceAgreement"),
		int64(1),
		clientNonce,
		claimCreatedAt,
	)
	inviteProofMAC := hmac.New(sha256.New, inviteSecret)
	inviteProofMAC.Write(claimTranscriptWithoutProof)
	inviteProof := inviteProofMAC.Sum(nil)
	claimTranscriptForSignature := append([]byte{}, claimTranscriptWithoutProof...)
	claimTranscriptForSignature = AppendField(claimTranscriptForSignature, inviteProof)
	deviceClaimSignature := vectorSign(t, keys["deviceSigning"], claimTranscriptForSignature)
	claimPlaintext := append([]byte{}, claimTranscriptForSignature...)
	claimPlaintext = AppendField(claimPlaintext, deviceClaimSignature)

	visibleClaimHeader := vectorTranscript(
		"MYCODEX-PAIRING-CLAIM-V1",
		int64(1),
		inviteID,
		tenantID,
		hostID,
		claimID,
		deviceID,
		public("deviceAgreement"),
		int64(1),
		clientNonce,
		int64(len(claimPlaintext)+16),
	)
	pairingSharedSecret := vectorECDH(t, keys["deviceAgreement"], &keys["hostAgreement"].PublicKey)
	pairingSaltDigest := sha256.Sum256(inviteSecret)
	pairingInfoInput := append([]byte{}, pairingPackageTranscript...)
	pairingInfoInput = AppendField(pairingInfoInput, hostPackageSignature)
	pairingInfoInput = append(pairingInfoInput, visibleClaimHeader...)
	pairingInfoDigest := sha256.Sum256(pairingInfoInput)
	pairingBaseKey := vectorHKDF(t, pairingSharedSecret, pairingSaltDigest[:], string(pairingInfoDigest[:]), 32)
	claimKey := vectorHKDF(t, pairingBaseKey, nil, "claim encryption", 32)
	claimCiphertext := vectorAESGCM(t, claimKey, claimNonce, claimPlaintext, visibleClaimHeader)

	pairingCodeTranscript := vectorTranscript("MYCODEX-PAIRING-CODE-V1", claimPlaintext)
	pairingCodeDigest := sha256.Sum256(pairingCodeTranscript)
	pairingCode := binary.BigEndian.Uint32(pairingCodeDigest[:4]) % 1000000

	approvalTranscript := vectorTranscript(
		"MYCODEX-PAIRING-APPROVAL-V1",
		int64(1),
		bindingID,
		tenantID,
		hostID,
		deviceID,
		public("hostSigning"),
		public("hostAgreement"),
		int64(1),
		public("deviceSigning"),
		public("deviceAgreement"),
		int64(1),
		relayPublic,
		relayFingerprint,
		approvedAt,
		int64(1),
	)
	hostApprovalSignature := vectorSign(t, keys["hostSigning"], approvalTranscript)
	approvalPlaintext := append([]byte{}, approvalTranscript...)
	approvalPlaintext = AppendField(approvalPlaintext, hostApprovalSignature)
	approvalHeader := vectorTranscript(
		"MYCODEX-PAIRING-APPROVAL-V1",
		int64(1),
		claimID,
		inviteID,
		tenantID,
		hostID,
		deviceID,
		"approved",
		int64(1),
		approvalNonce,
		int64(len(approvalPlaintext)+16),
	)
	approvalKey := vectorHKDF(t, pairingBaseKey, nil, "approval encryption", 32)
	approvalCiphertext := vectorAESGCM(t, approvalKey, approvalNonce, approvalPlaintext, approvalHeader)

	relayChallengeTranscript := vectorTranscript(
		"MYCODEX-RELAY-CHALLENGE-V1",
		int64(1),
		relayFingerprint,
		challengeID,
		challengeValue,
		"device",
		deviceID,
		"host",
		hostID,
		"websocket",
		challengeAt,
		challengeExpiry,
	)
	relayChallengeSignature := vectorSign(t, keys["relaySigning"], relayChallengeTranscript)
	relayProofTranscript := vectorTranscript(
		"MYCODEX-RELAY-PROOF-V1",
		int64(1),
		relayChallengeTranscript,
		relayChallengeSignature,
		"device",
		deviceID,
	)
	deviceProofSignature := vectorSign(t, keys["deviceSigning"], relayProofTranscript)

	sessionClientPublic := public("deviceAgreement")
	sessionServerPublic := public("sessionServerEphemeral")
	sessionClientHelloTranscript := vectorTranscript(
		"MYCODEX-SESSION-HELLO-V1",
		int64(1),
		tenantID,
		hostID,
		deviceID,
		bindingID,
		int64(1),
		int64(1),
		sessionClientPublic,
		sessionClientNonce,
		clientHelloAt,
	)
	sessionClientSignature := vectorSign(t, keys["deviceSigning"], sessionClientHelloTranscript)
	sessionServerHelloTranscript := append([]byte{}, sessionClientHelloTranscript...)
	sessionServerHelloTranscript = AppendField(sessionServerHelloTranscript, sessionClientSignature)
	sessionServerHelloTranscript = AppendInt64(sessionServerHelloTranscript, 1)
	sessionServerHelloTranscript = AppendField(sessionServerHelloTranscript, sessionServerPublic)
	sessionServerHelloTranscript = AppendField(sessionServerHelloTranscript, sessionServerNonce)
	sessionServerHelloTranscript = AppendInt64(sessionServerHelloTranscript, serverHelloAt)
	sessionServerSignature := vectorSign(t, keys["hostSigning"], sessionServerHelloTranscript)
	sessionCompleteTranscript := append([]byte{}, sessionServerHelloTranscript...)
	sessionCompleteTranscript = AppendField(sessionCompleteTranscript, sessionServerSignature)

	sessionSharedSecret := vectorECDH(t, keys["deviceAgreement"], &keys["sessionServerEphemeral"].PublicKey)
	sessionSaltInput := append([]byte{}, sessionClientNonce...)
	sessionSaltInput = append(sessionSaltInput, sessionServerNonce...)
	sessionSaltDigest := sha256.Sum256(sessionSaltInput)
	sessionMaster := vectorHKDF(t, sessionSharedSecret, sessionSaltDigest[:], string(sessionCompleteTranscript), 32)
	androidToWindowsKey := vectorHKDF(t, sessionMaster, nil, "android to windows key", 32)
	windowsToAndroidKey := vectorHKDF(t, sessionMaster, nil, "windows to android key", 32)
	androidNoncePrefix := vectorHKDF(t, sessionMaster, nil, "android to windows nonce prefix", 4)
	windowsNoncePrefix := vectorHKDF(t, sessionMaster, nil, "windows to android nonce prefix", 4)
	sessionConfirmationKey := vectorHKDF(t, sessionMaster, nil, "session confirmation", 32)
	androidConfirmTranscript := vectorTranscript(
		"MYCODEX-SESSION-CONFIRM-V1",
		sessionCompleteTranscript,
		"android",
	)
	windowsConfirmTranscript := vectorTranscript(
		"MYCODEX-SESSION-CONFIRM-V1",
		sessionCompleteTranscript,
		"windows",
	)
	androidConfirmMAC := hmac.New(sha256.New, sessionConfirmationKey)
	androidConfirmMAC.Write(androidConfirmTranscript)
	androidConfirm := androidConfirmMAC.Sum(nil)
	windowsConfirmMAC := hmac.New(sha256.New, sessionConfirmationKey)
	windowsConfirmMAC.Write(windowsConfirmTranscript)
	windowsConfirm := windowsConfirmMAC.Sum(nil)

	envelopePlaintext := []byte(`{"type":"remote/ping","value":"hello secure remote"}`)
	envelopeNonce := append([]byte{}, androidNoncePrefix...)
	envelopeNonce = appendUint64(envelopeNonce, 1)
	envelopeAAD := vectorTranscript(
		"MYCODEX-ENVELOPE-AAD-V1",
		int64(1),
		sessionID,
		tenantID,
		hostID,
		deviceID,
		"android",
		"rpc.request",
		messageID,
		uint64(1),
		messageAt,
		"encrypted-json",
		envelopeNonce,
		int64(len(envelopePlaintext)+16),
	)
	envelopeCiphertext := vectorAESGCM(t, androidToWindowsKey, envelopeNonce, envelopePlaintext, envelopeAAD)

	return secureRemoteVector{
		ProtocolVersion: 1,
		Inputs: map[string]any{
			"privateScalars": map[string]string{
				"relaySigning":           "1",
				"hostSigning":            "2",
				"hostAgreement":          "3",
				"deviceSigning":          "4",
				"deviceAgreement":        "5",
				"sessionClientEphemeral": "5",
				"sessionServerEphemeral": "6",
			},
			"strings": map[string]string{
				"relayUrl":              relayURL,
				"hostName":              "Demo Windows Host",
				"deviceName":            "Demo Android Device",
				"platform":              "android",
				"appVersion":            "1.0.0",
				"approvalStatus":        "approved",
				"messageType":           "rpc.request",
				"senderRole":            "android",
				"payloadEncoding":       "encrypted-json",
				"envelopePlaintextUtf8": string(envelopePlaintext),
			},
			"inviteSecretHex":       hex.EncodeToString(inviteSecret),
			"clientNonceHex":        hex.EncodeToString(clientNonce),
			"claimNonceHex":         hex.EncodeToString(claimNonce),
			"approvalNonceHex":      hex.EncodeToString(approvalNonce),
			"challengeValueHex":     hex.EncodeToString(challengeValue),
			"sessionClientNonceHex": hex.EncodeToString(sessionClientNonce),
			"sessionServerNonceHex": hex.EncodeToString(sessionServerNonce),
			"ids": map[string]string{
				"tenantId": tenantID, "hostId": hostID, "deviceId": deviceID,
				"inviteId": inviteID, "claimId": claimID, "challengeId": challengeID,
				"bindingId": bindingID, "sessionId": sessionID, "messageId": messageID,
			},
			"unixMilliseconds": map[string]int64{
				"inviteExpiresAt": inviteExpiresAt, "claimCreatedAt": claimCreatedAt,
				"approvedAt": approvedAt, "challengeIssuedAt": challengeAt,
				"challengeExpiresAt": challengeExpiry, "clientHelloCreatedAt": clientHelloAt,
				"serverHelloCreatedAt": serverHelloAt, "messageCreatedAt": messageAt,
			},
		},
		PublicKeys: map[string]any{
			"relaySigning":           vectorB64(relayPublic),
			"hostSigning":            vectorB64(public("hostSigning")),
			"hostAgreement":          vectorB64(public("hostAgreement")),
			"deviceSigning":          vectorB64(public("deviceSigning")),
			"deviceAgreement":        vectorB64(public("deviceAgreement")),
			"sessionClientEphemeral": vectorB64(sessionClientPublic),
			"sessionServerEphemeral": vectorB64(sessionServerPublic),
			"relayFingerprintSha256": vectorB64(relayFingerprint),
		},
		Transcripts: map[string]any{
			"pairingPackage":           vectorB64(pairingPackageTranscript),
			"visibleClaimHeader":       vectorB64(visibleClaimHeader),
			"pairingClaimWithoutProof": vectorB64(claimTranscriptWithoutProof),
			"pairingClaimForSignature": vectorB64(claimTranscriptForSignature),
			"pairingApproval":          vectorB64(approvalTranscript),
			"approvalHeader":           vectorB64(approvalHeader),
			"relayChallenge":           vectorB64(relayChallengeTranscript),
			"relayProof":               vectorB64(relayProofTranscript),
			"sessionClientHello":       vectorB64(sessionClientHelloTranscript),
			"sessionServerHello":       vectorB64(sessionServerHelloTranscript),
			"sessionComplete":          vectorB64(sessionCompleteTranscript),
			"sessionConfirmAndroid":    vectorB64(androidConfirmTranscript),
			"sessionConfirmWindows":    vectorB64(windowsConfirmTranscript),
			"envelopeAAD":              vectorB64(envelopeAAD),
		},
		Signatures: map[string]any{
			"hostPairingPackage":  vectorB64(hostPackageSignature),
			"devicePairingClaim":  vectorB64(deviceClaimSignature),
			"hostPairingApproval": vectorB64(hostApprovalSignature),
			"relayChallenge":      vectorB64(relayChallengeSignature),
			"deviceRelayProof":    vectorB64(deviceProofSignature),
			"deviceSessionHello":  vectorB64(sessionClientSignature),
			"hostSessionHello":    vectorB64(sessionServerSignature),
		},
		Pairing: map[string]any{
			"ecdhSharedSecret":   vectorB64(pairingSharedSecret),
			"saltSha256":         vectorB64(pairingSaltDigest[:]),
			"infoSha256":         vectorB64(pairingInfoDigest[:]),
			"pairingBaseKey":     vectorB64(pairingBaseKey),
			"claimKey":           vectorB64(claimKey),
			"inviteProof":        vectorB64(inviteProof),
			"claimPlaintext":     vectorB64(claimPlaintext),
			"claimCiphertext":    vectorB64(claimCiphertext),
			"pairingCode":        formatPairingCode(pairingCode),
			"approvalKey":        vectorB64(approvalKey),
			"approvalPlaintext":  vectorB64(approvalPlaintext),
			"approvalCiphertext": vectorB64(approvalCiphertext),
		},
		Session: map[string]any{
			"ecdhSharedSecret":            vectorB64(sessionSharedSecret),
			"saltSha256":                  vectorB64(sessionSaltDigest[:]),
			"sessionMaster":               vectorB64(sessionMaster),
			"androidToWindowsKey":         vectorB64(androidToWindowsKey),
			"windowsToAndroidKey":         vectorB64(windowsToAndroidKey),
			"androidToWindowsNoncePrefix": vectorB64(androidNoncePrefix),
			"windowsToAndroidNoncePrefix": vectorB64(windowsNoncePrefix),
			"confirmationKey":             vectorB64(sessionConfirmationKey),
			"androidConfirmation":         vectorB64(androidConfirm),
			"windowsConfirmation":         vectorB64(windowsConfirm),
		},
		Envelope: map[string]any{
			"sequence":   1,
			"nonce":      vectorB64(envelopeNonce),
			"plaintext":  vectorB64(envelopePlaintext),
			"ciphertext": vectorB64(envelopeCiphertext),
		},
	}
}

func vectorPrivateKey(t *testing.T, scalar int64) *ecdsa.PrivateKey {
	t.Helper()
	curve := elliptic.P256()
	d := big.NewInt(scalar)
	x, y := curve.ScalarBaseMult(d.FillBytes(make([]byte, 32)))
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
}

func vectorTranscript(fields ...any) []byte {
	var result []byte
	for _, field := range fields {
		switch value := field.(type) {
		case string:
			result = AppendString(result, value)
		case []byte:
			result = AppendField(result, value)
		case int64:
			result = AppendInt64(result, value)
		case uint64:
			result = appendUint64(result, value)
		default:
			panic("unsupported vector transcript field")
		}
	}
	return result
}

func appendUint64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

func vectorSign(t *testing.T, key *ecdsa.PrivateKey, transcript []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(transcript)
	order := key.Curve.Params().N
	keyBytes := key.D.FillBytes(make([]byte, 32))
	hashNumber := new(big.Int).SetBytes(digest[:])
	hashNumber.Mod(hashNumber, order)
	hashBytes := hashNumber.FillBytes(make([]byte, 32))
	v := bytes.Repeat([]byte{0x01}, 32)
	k := make([]byte, 32)
	k = vectorHMAC(k, append(append(append(append([]byte{}, v...), 0x00), keyBytes...), hashBytes...))
	v = vectorHMAC(k, v)
	k = vectorHMAC(k, append(append(append(append([]byte{}, v...), 0x01), keyBytes...), hashBytes...))
	v = vectorHMAC(k, v)

	for {
		v = vectorHMAC(k, v)
		nonce := new(big.Int).SetBytes(v)
		if nonce.Sign() > 0 && nonce.Cmp(order) < 0 {
			x, _ := key.Curve.ScalarBaseMult(nonce.FillBytes(make([]byte, 32)))
			r := new(big.Int).Mod(x, order)
			if r.Sign() != 0 {
				s := new(big.Int).Mul(r, key.D)
				s.Add(s, new(big.Int).SetBytes(digest[:]))
				s.Mul(s, new(big.Int).ModInverse(nonce, order))
				s.Mod(s, order)
				if s.Sign() != 0 {
					halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
					if s.Cmp(halfOrder) > 0 {
						s.Sub(order, s)
					}
					signature := make([]byte, 64)
					r.FillBytes(signature[:32])
					s.FillBytes(signature[32:])
					return signature
				}
			}
		}
		k = vectorHMAC(k, append(append([]byte{}, v...), 0x00))
		v = vectorHMAC(k, v)
	}
}

func vectorHMAC(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(value)
	return mac.Sum(nil)
}

func vectorECDH(t *testing.T, private *ecdsa.PrivateKey, public *ecdsa.PublicKey) []byte {
	t.Helper()
	x, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.FillBytes(make([]byte, 32)))
	if x == nil {
		t.Fatal("ECDH produced the point at infinity")
	}
	return x.FillBytes(make([]byte, 32))
}

func vectorHKDF(t *testing.T, secret, salt []byte, info string, size int) []byte {
	t.Helper()
	value, err := hkdf.Key(sha256.New, secret, salt, info, size)
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}
	return value
}

func vectorAESGCM(t *testing.T, key, nonce, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM failed: %v", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad)
}

func vectorB64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func vectorBytes(start byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = start + byte(i)
	}
	return result
}

func formatPairingCode(value uint32) string {
	var digits [6]byte
	for index := len(digits) - 1; index >= 0; index-- {
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[:])
}
