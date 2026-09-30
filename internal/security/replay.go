package security

import (
	"sync"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

// MemoryReplayGuard atomically records consumed grant IDs until expiry. It is
// process-local; production multi-replica deployments should replace it with a
// durable implementation of the same consume semantics.
type MemoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{seen: make(map[string]time.Time)}
}

// Consume succeeds exactly once for an unexpired grant ID, even under
// concurrent calls.
func (g *MemoryReplayGuard) Consume(grantID string, expiresAt, now time.Time) error {
	if g == nil {
		return model.NewError(model.CodeInvalidInput, "replay guard is required")
	}
	if grantID == "" || now.IsZero() || expiresAt.IsZero() {
		return model.NewError(model.CodeInvalidInput, "grant ID, expiry, and current time are required")
	}
	now = now.UTC()
	expiresAt = expiresAt.UTC()
	if !now.Before(expiresAt) {
		return model.NewError(model.CodeGrantExpired, "delegation grant has expired")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]time.Time)
	}
	for id, expiry := range g.seen {
		if !now.Before(expiry) {
			delete(g.seen, id)
		}
	}
	if _, exists := g.seen[grantID]; exists {
		return model.NewError(model.CodeReplayedGrant, "delegation grant was already consumed")
	}
	g.seen[grantID] = expiresAt
	return nil
}

func (g *MemoryReplayGuard) ConsumeGrant(grant model.DelegationGrant, now time.Time) error {
	return g.Consume(grant.GrantID, grant.ExpiresAt, now)
}

func (g *MemoryReplayGuard) Purge(now time.Time) int {
	if g == nil || now.IsZero() {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	removed := 0
	for id, expiry := range g.seen {
		if !now.Before(expiry) {
			delete(g.seen, id)
			removed++
		}
	}
	return removed
}

func (g *MemoryReplayGuard) Len() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
