package reasoner

import (
	"context"
	"errors"
	"fmt"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
)

// Fallback tries Primary first and invokes Secondary only when Primary
// returns an error. A successful but inconclusive primary report is preserved.
type Fallback struct {
	Primary   ports.Reasoner
	Secondary ports.Reasoner
}

var _ ports.Reasoner = Fallback{}

func NewFallback(primary, secondary ports.Reasoner) (*Fallback, error) {
	if primary == nil || secondary == nil {
		return nil, model.NewError(model.CodeInvalidInput, "primary and fallback reasoners are required")
	}
	return &Fallback{Primary: primary, Secondary: secondary}, nil
}

func (r Fallback) Diagnose(ctx context.Context, request model.InvestigationRequest, evidence []model.EvidenceItem) (model.DiagnosisReport, error) {
	if r.Primary == nil || r.Secondary == nil {
		return model.DiagnosisReport{}, model.NewError(model.CodeInvalidInput, "fallback reasoner is incomplete")
	}
	report, primaryErr := r.Primary.Diagnose(ctx, request, evidence)
	if primaryErr == nil {
		return report, nil
	}
	report, fallbackErr := r.Secondary.Diagnose(ctx, request, evidence)
	if fallbackErr == nil {
		return report, nil
	}
	return model.DiagnosisReport{}, errors.Join(
		fmt.Errorf("primary reasoner: %w", primaryErr),
		fmt.Errorf("fallback reasoner: %w", fallbackErr),
	)
}
