package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

func AppendField(dst []byte, value []byte) []byte {
	if uint64(len(value)) > math.MaxUint32 {
		panic("canonical field exceeds uint32 length")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func AppendString(dst []byte, value string) []byte {
	return AppendField(dst, []byte(value))
}

func AppendInt64(dst []byte, value int64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	return append(dst, encoded[:]...)
}

func DecodeSEC1PublicKey(value string) (*ecdsa.PublicKey, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode SEC1 public key: %w", err)
	}
	if len(encoded) != 65 || encoded[0] != 0x04 {
		return nil, fmt.Errorf("SEC1 public key must be 65-byte uncompressed P-256")
	}
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, encoded)
	if x == nil || y == nil {
		return nil, fmt.Errorf("SEC1 public key is not a valid P-256 point")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func VerifyRawSignature(key *ecdsa.PublicKey, transcript []byte, signature string) bool {
	if key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil {
		return false
	}
	encoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(encoded) != 64 {
		return false
	}
	digest := sha256.Sum256(transcript)
	r := new(big.Int).SetBytes(encoded[:32])
	s := new(big.Int).SetBytes(encoded[32:])
	return ecdsa.Verify(key, digest[:], r, s)
}
