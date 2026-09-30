// Package security implements AegisSRE's delegation trust boundary.
package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func decodeBase64Key(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("key is empty")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("key is not valid base64")
}

// ParsePublicKeyBase64 parses padded or unpadded standard/URL base64.
func ParsePublicKeyBase64(value string) (ed25519.PublicKey, error) {
	decoded, err := decodeBase64Key(value)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("parse Ed25519 public key: got %d bytes, want %d", len(decoded), ed25519.PublicKeySize)
	}
	key := make(ed25519.PublicKey, len(decoded))
	copy(key, decoded)
	return key, nil
}

// ParsePrivateKeyBase64 accepts either a 32-byte Ed25519 seed or a 64-byte
// private key. A defensive copy is always returned.
func ParsePrivateKeyBase64(value string) (ed25519.PrivateKey, error) {
	decoded, err := decodeBase64Key(value)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 private key: %w", err)
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		key := make(ed25519.PrivateKey, len(decoded))
		copy(key, decoded)
		return key, nil
	default:
		return nil, fmt.Errorf("parse Ed25519 private key: got %d bytes, want %d-byte seed or %d-byte key", len(decoded), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func EncodePublicKeyBase64(key ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(key)
}

func EncodePrivateKeyBase64(key ed25519.PrivateKey) string {
	return base64.RawStdEncoding.EncodeToString(key)
}
