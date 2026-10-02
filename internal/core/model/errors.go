// Package model contains AegisSRE's protocol-independent domain contracts.
package model

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable, machine-readable failure category used across A2A,
// MCP, audit records, and tests. Human-readable messages are deliberately not
// part of the protocol contract.
type ErrorCode string

const (
	CodeInvalidInput           ErrorCode = "INVALID_INPUT"
	CodeInvalidStateTransition ErrorCode = "INVALID_STATE_TRANSITION"
	CodeOutOfScope             ErrorCode = "OUT_OF_SCOPE"
	CodeDelegationRequired     ErrorCode = "DELEGATION_REQUIRED"
	CodePolicyDenied           ErrorCode = "POLICY_DENIED"
	CodeInvalidSignature       ErrorCode = "INVALID_SIGNATURE"
	CodeGrantNotYetValid       ErrorCode = "GRANT_NOT_YET_VALID"
	CodeGrantExpired           ErrorCode = "GRANT_EXPIRED"
	CodeReplayedGrant          ErrorCode = "REPLAYED_GRANT"
	CodeExecutionPending       ErrorCode = "EXECUTION_PENDING"
	CodeStalePrecondition      ErrorCode = "STALE_PRECONDITION"
	CodeToolBudgetExceeded     ErrorCode = "TOOL_BUDGET_EXCEEDED"
	CodeInconclusiveDiagnosis  ErrorCode = "INCONCLUSIVE_DIAGNOSIS"
	CodeExecutionFailed        ErrorCode = "EXECUTION_FAILED"
)

// CodedError retains a stable code while still participating in Go error
// wrapping. It must not contain credentials or raw telemetry.
type CodedError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

func (e *CodedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *CodedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func NewError(code ErrorCode, message string) error {
	return &CodedError{Code: code, Message: message}
}

func WrapError(code ErrorCode, message string, cause error) error {
	return &CodedError{Code: code, Message: message, Cause: cause}
}

// ErrorCodeOf extracts an AegisSRE code through an error chain.
func ErrorCodeOf(err error) (ErrorCode, bool) {
	var coded *CodedError
	if !errors.As(err, &coded) {
		return "", false
	}
	return coded.Code, true
}
