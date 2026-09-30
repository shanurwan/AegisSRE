package model

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

const SchemaVersionV1 = "v1"

func requireText(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return NewError(CodeInvalidInput, field+" is required")
	}
	if strings.TrimSpace(value) != value {
		return NewError(CodeInvalidInput, field+" must not have surrounding whitespace")
	}
	if len(value) > 512 {
		return NewError(CodeInvalidInput, field+" is too long")
	}
	return nil
}

func requireTime(field string, value time.Time) error {
	if value.IsZero() {
		return NewError(CodeInvalidInput, field+" is required")
	}
	return nil
}

func validateConfidence(value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		return NewError(CodeInvalidInput, "confidence must be between 0 and 1")
	}
	return nil
}

func validateUniqueStrings(field string, values []string, requireOne bool) error {
	if requireOne && len(values) == 0 {
		return NewError(CodeInvalidInput, field+" must not be empty")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := requireText(field, value); err != nil {
			return err
		}
		if _, ok := seen[value]; ok {
			return NewError(CodeInvalidInput, field+" contains a duplicate")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateDigest(field, value string) error {
	if len(value) != sha256.Size*2 {
		return NewError(CodeInvalidInput, field+" must be a SHA-256 hex digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return NewError(CodeInvalidInput, field+" must be lowercase hexadecimal")
	}
	return nil
}

func digestJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal digest input: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func digestEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func utc(value time.Time) time.Time {
	if value.IsZero() {
		return value
	}
	return value.UTC()
}
