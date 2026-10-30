// Package discovery decides where Monitor sends each A2A message. Static
// addresses are the default; the NANDA adapter resolves and verifies peers
// through the NANDA Index. Either way the grant, mTLS and workload policy
// remain the authority boundary.
package discovery

import (
	"context"
	"fmt"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
)

// Static resolves each peer to a configured base URL.
type Static map[model.AgentID]string

func (s Static) Resolve(_ context.Context, agent model.AgentID) (string, error) {
	endpoint, ok := s[agent]
	if !ok || endpoint == "" {
		return "", model.NewError(model.CodeOutOfScope, "no A2A endpoint is configured for this peer")
	}
	return endpoint, nil
}

// Forgetter is implemented by resolvers that cache verified endpoints.
type Forgetter interface {
	Forget(model.AgentID)
}

// Messenger sends every message to the endpoint the resolver returns for its
// recipient, so the caller's configured address is never trusted on its own.
type Messenger struct {
	Resolver ports.PeerResolver
	Next     ports.PeerMessenger
}

func (m Messenger) Send(ctx context.Context, _ string, envelope model.Envelope, response any) error {
	endpoint, err := m.Resolver.Resolve(ctx, envelope.Recipient)
	if err != nil {
		return err
	}
	if err := m.Next.Send(ctx, endpoint, envelope, response); err != nil {
		// A peer that moved or rotated keys is re-resolved on the next attempt.
		if forgetter, ok := m.Resolver.(Forgetter); ok {
			forgetter.Forget(envelope.Recipient)
		}
		return fmt.Errorf("send to %s: %w", envelope.Recipient, err)
	}
	return nil
}
