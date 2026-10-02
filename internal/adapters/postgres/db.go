// Package postgres provides durable PostgreSQL adapters for AegisSRE control
// state. The stores deliberately keep provider credentials and raw telemetry
// out of the database.
package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/security"
)

const (
	maxLeaseDuration = 5 * time.Minute
	maxBatchSize     = 100
	defaultRetention = 90 * 24 * time.Hour
)

// DB is implemented by pgxpool.Pool and is intentionally small enough for
// fault-injection adapters in tests.
type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

func randomToken() (string, error) {
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate database lease token: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func signedGrantFingerprint(grant model.DelegationGrant) ([sha256.Size]byte, error) {
	if err := grant.ValidateSigned(); err != nil {
		return [sha256.Size]byte{}, err
	}
	canonical, err := security.CanonicalGrantBytes(grant)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return authorizationFingerprint(
		canonical, grant.Signature.Algorithm, grant.Signature.KeyID, grant.Signature.Value,
	), nil
}

func signedReportFingerprint(request model.IncidentReportRequest) ([sha256.Size]byte, error) {
	if err := request.ValidateSigned(); err != nil {
		return [sha256.Size]byte{}, err
	}
	canonical, err := security.CanonicalReportRequestBytes(request)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return authorizationFingerprint(
		canonical, request.Signature.Algorithm, request.Signature.KeyID, request.Signature.Value,
	), nil
}

func authorizationFingerprint(canonical []byte, signatureParts ...string) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write(canonical)
	for _, part := range signatureParts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], hash.Sum(nil))
	return fingerprint
}

func marshalBounded(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal durable state: %w", err)
	}
	if len(data) == 0 || len(data) > 128<<10 {
		return nil, model.NewError(model.CodeInvalidInput, "durable state payload exceeds its size limit")
	}
	return data, nil
}

func validateOwner(owner string) error {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(owner) != owner || len(owner) > 512 {
		return model.NewError(model.CodeInvalidInput, "lease owner is invalid")
	}
	return nil
}

func validateLease(lease time.Duration) error {
	if lease < time.Second || lease > maxLeaseDuration {
		return model.NewError(model.CodeInvalidInput, "lease duration must be between one second and five minutes")
	}
	return nil
}

func validateBatch(limit int) error {
	if limit < 1 || limit > maxBatchSize {
		return model.NewError(model.CodeInvalidInput, "batch size must be between one and one hundred")
	}
	return nil
}

func validSafeCode(code model.ErrorCode) bool {
	if code == "" || len(code) > 512 {
		return false
	}
	for _, character := range string(code) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
