// Package authn binds verified mTLS workload identities to AegisSRE roles at
// HTTP transport boundaries.
package authn

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/platform/tlsconfig"
)

type principalContextKey struct{}

// Principal is an authenticated workload identity and its configured AegisSRE
// role. Callers must not construct a Principal from headers or envelope fields.
type Principal struct {
	Identity string
	Agent    model.AgentID
}

// Authorizer maps exact URI SANs to roles and permits only the roles required
// by one destination. Its middleware authenticates and authorizes before it
// invokes the protocol handler, so unauthorized bodies are never decoded.
type Authorizer struct {
	byIdentity map[string]model.AgentID
	allowed    map[model.AgentID]struct{}
}

// NewRoleAuthorizer applies AegisSRE's fixed caller matrix to recipient.
// identities maps each caller role to the one exact URI SAN issued to it.
func NewRoleAuthorizer(recipient model.AgentID, identities map[model.AgentID]string) (*Authorizer, error) {
	allowed, err := AllowedCallers(recipient)
	if err != nil {
		return nil, err
	}
	return NewAuthorizer(identities, allowed...)
}

// NewAuthorizer constructs an explicit allowlist. NewRoleAuthorizer should be
// preferred for the five standard services; this constructor supports narrow
// administrative endpoints without weakening the fixed role matrix.
func NewAuthorizer(identities map[model.AgentID]string, allowed ...model.AgentID) (*Authorizer, error) {
	if len(allowed) == 0 {
		return &Authorizer{byIdentity: map[string]model.AgentID{}, allowed: map[model.AgentID]struct{}{}}, nil
	}
	byIdentity := make(map[string]model.AgentID, len(allowed))
	allowedSet := make(map[model.AgentID]struct{}, len(allowed))
	for _, agent := range allowed {
		if !knownAgent(agent) {
			return nil, errors.New("mTLS allowlist contains an unknown AegisSRE role")
		}
		if _, duplicate := allowedSet[agent]; duplicate {
			return nil, errors.New("mTLS allowlist contains a duplicate AegisSRE role")
		}
		identity, ok := identities[agent]
		if !ok || !validIdentity(identity) {
			return nil, errors.New("mTLS allowlist is missing a valid workload URI identity")
		}
		if _, duplicate := byIdentity[identity]; duplicate {
			return nil, errors.New("mTLS workload URI identity is assigned to multiple roles")
		}
		allowedSet[agent] = struct{}{}
		byIdentity[identity] = agent
	}
	return &Authorizer{byIdentity: byIdentity, allowed: allowedSet}, nil
}

// Middleware rejects unauthenticated or unauthorized peers without reading the
// request body. The TLS listener must use tlsconfig.LoadServer (or equivalent
// RequireAndVerifyClientCert settings) so VerifiedChains is authoritative.
func (a *Authorizer) Middleware(next http.Handler) http.Handler {
	if next == nil {
		panic("authn: next handler is nil")
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if a == nil || request == nil || request.TLS == nil {
			reject(writer, http.StatusUnauthorized)
			return
		}
		identity, err := tlsconfig.VerifiedPeerIdentity(*request.TLS)
		if err != nil {
			reject(writer, http.StatusUnauthorized)
			return
		}
		agent, known := a.byIdentity[identity]
		if !known {
			reject(writer, http.StatusForbidden)
			return
		}
		if _, allowed := a.allowed[agent]; !allowed {
			reject(writer, http.StatusForbidden)
			return
		}
		principal := Principal{Identity: identity, Agent: agent}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal)))
	})
}

// PrincipalFromContext returns the identity established by Middleware.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok && principal.Identity != "" && principal.Agent != ""
}

// RequireAgent binds an authenticated transport principal to an A2A envelope's
// claimed sender. It prevents a valid certificate for one role from claiming a
// different sender in structured protocol data.
func RequireAgent(ctx context.Context, claimed model.AgentID) error {
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		return model.NewError(model.CodeDelegationRequired, "authenticated transport identity is required")
	}
	if principal.Agent != claimed {
		return model.NewError(model.CodeDelegationRequired, "A2A sender does not match authenticated transport identity")
	}
	return nil
}

// AllowedCallers is the production communication graph. An empty list for
// Monitor is intentional: Monitor self-polls and accepts no workflow request.
func AllowedCallers(recipient model.AgentID) ([]model.AgentID, error) {
	switch recipient {
	case model.AgentMonitor:
		return nil, nil
	case model.AgentInvestigator:
		return []model.AgentID{model.AgentMonitor}, nil
	case model.AgentOperator:
		return []model.AgentID{model.AgentMonitor}, nil
	case model.AgentMCPObserve:
		return []model.AgentID{model.AgentMonitor, model.AgentInvestigator}, nil
	case model.AgentMCPAction:
		return []model.AgentID{model.AgentOperator}, nil
	default:
		return nil, errors.New("mTLS destination is not a known AegisSRE role")
	}
}

func reject(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	http.Error(writer, http.StatusText(status), status)
}

func knownAgent(agent model.AgentID) bool {
	switch agent {
	case model.AgentMonitor, model.AgentInvestigator, model.AgentOperator,
		model.AgentMCPObserve, model.AgentMCPAction:
		return true
	default:
		return false
	}
}

func validIdentity(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 512 {
		return false
	}
	identity, err := url.Parse(value)
	return err == nil && identity.Scheme != "" && identity.User == nil &&
		identity.RawQuery == "" && identity.Fragment == "" && identity.String() == value
}
