// Package security implements AegisSRE's delegation trust boundary.
package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const maxPrivateKeyFileSize = 4096

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

// LoadPrivateKeyFile reads a bounded regular file containing only the base64
// Ed25519 seed/private key. File mounts are preferred over environment values
// because they avoid copying long-lived signing material into process env.
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("Ed25519 private-key file is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read Ed25519 private-key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPrivateKeyFileSize {
		return nil, errors.New("Ed25519 private-key file is empty, oversized, or not regular")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path, never request input
	if err != nil {
		return nil, fmt.Errorf("read Ed25519 private-key file: %w", err)
	}
	return ParsePrivateKeyBase64(string(data))
}

func EncodePublicKeyBase64(key ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(key)
}

func EncodePrivateKeyBase64(key ed25519.PrivateKey) string {
	return base64.RawStdEncoding.EncodeToString(key)
}
