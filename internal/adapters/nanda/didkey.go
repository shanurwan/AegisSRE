package nanda

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// did:key for Ed25519 is "did:key:z" + base58btc(0xed 0x01 || public key),
// the form the NANDA concierge demo uses for agent identity.
const (
	didKeyPrefix   = "did:key:z"
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var ed25519Multicodec = []byte{0xed, 0x01}

// DIDKey encodes an Ed25519 public key as a did:key identifier.
func DIDKey(publicKey ed25519.PublicKey) string {
	payload := append(append([]byte{}, ed25519Multicodec...), publicKey...)
	return didKeyPrefix + base58Encode(payload)
}

// ParseDIDKey decodes an Ed25519 did:key identifier.
func ParseDIDKey(did string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(strings.TrimSpace(did), didKeyPrefix)
	if !ok {
		return nil, errors.New("not a base58btc did:key identifier")
	}
	payload, err := base58Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode did:key: %w", err)
	}
	if len(payload) != len(ed25519Multicodec)+ed25519.PublicKeySize ||
		payload[0] != ed25519Multicodec[0] || payload[1] != ed25519Multicodec[1] {
		return nil, errors.New("did:key is not an Ed25519 public key")
	}
	return ed25519.PublicKey(payload[len(ed25519Multicodec):]), nil
}

func base58Encode(data []byte) string {
	number := new(big.Int).SetBytes(data)
	radix, remainder := big.NewInt(58), new(big.Int)
	var encoded []byte
	for number.Sign() > 0 {
		number.DivMod(number, radix, remainder)
		encoded = append(encoded, base58Alphabet[remainder.Int64()])
	}
	for _, value := range data {
		if value != 0 {
			break
		}
		encoded = append(encoded, base58Alphabet[0])
	}
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	return string(encoded)
}

func base58Decode(text string) ([]byte, error) {
	if text == "" || len(text) > 128 {
		return nil, errors.New("base58 value is empty or too long")
	}
	number, radix := new(big.Int), big.NewInt(58)
	for _, character := range text {
		index := strings.IndexRune(base58Alphabet, character)
		if index < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", character)
		}
		number.Mul(number, radix)
		number.Add(number, big.NewInt(int64(index)))
	}
	decoded := number.Bytes()
	leading := 0
	for leading < len(text) && text[leading] == base58Alphabet[0] {
		leading++
	}
	return append(make([]byte, leading), decoded...), nil
}
