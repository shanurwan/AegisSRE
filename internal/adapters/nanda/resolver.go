package nanda

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const agentCardPath = "/.well-known/agent-card.json"

// Peer is what Monitor expects of one A2A peer before it will talk to it.
type Peer struct {
	// ID is the peer's urn:air: identifier in the NANDA Index.
	ID string
	// Key is the pinned Ed25519 key that must have signed the peer's
	// AgentFacts. The Index says where a peer is; this key says who it is.
	Key ed25519.PublicKey
	// Skill is the A2A skill ID the peer's role requires.
	Skill string
}

// Resolver finds A2A peers through the NANDA Index and returns an endpoint
// only after the Index entry, Agent Card and signed AgentFacts all agree.
type Resolver struct {
	Index IndexClient
	Peers map[model.AgentID]Peer
	// PeerClient returns the HTTP client used to fetch a peer's Agent Card and
	// AgentFacts: the same mTLS client used for the peer's A2A traffic.
	PeerClient func(model.AgentID) *http.Client
	// AllowHTTP accepts plaintext Agent Card URLs, for local fixtures only.
	AllowHTTP bool
	TTL       time.Duration
	Now       func() time.Time

	mu    sync.Mutex
	cache map[model.AgentID]cachedEndpoint
}

type cachedEndpoint struct {
	endpoint string
	expires  time.Time
}

// Resolve returns the verified A2A base URL of agent.
func (r *Resolver) Resolve(ctx context.Context, agent model.AgentID) (string, error) {
	now := r.now()
	r.mu.Lock()
	if cached, ok := r.cache[agent]; ok && now.Before(cached.expires) {
		r.mu.Unlock()
		return cached.endpoint, nil
	}
	r.mu.Unlock()

	endpoint, err := r.resolve(ctx, agent)
	if err != nil {
		r.Forget(agent)
		return "", fmt.Errorf("NANDA discovery of %s: %w", agent, err)
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[model.AgentID]cachedEndpoint)
	}
	r.cache[agent] = cachedEndpoint{endpoint: endpoint, expires: now.Add(r.TTL)}
	r.mu.Unlock()
	return endpoint, nil
}

// Forget drops a cached endpoint so the next call resolves and verifies again.
func (r *Resolver) Forget(agent model.AgentID) {
	r.mu.Lock()
	delete(r.cache, agent)
	r.mu.Unlock()
}

func (r *Resolver) resolve(ctx context.Context, agent model.AgentID) (string, error) {
	peer, ok := r.Peers[agent]
	if !ok {
		return "", model.NewError(model.CodeOutOfScope, "no NANDA identity is configured for this peer")
	}
	domain, err := PublisherDomain(peer.ID)
	if err != nil {
		return "", err
	}
	entry, err := r.Index.Resolve(ctx, peer.ID)
	if err != nil {
		return "", err
	}
	switch {
	case entry.Type != A2ACardMediaType:
		return "", fmt.Errorf("Index entry type is %q, not an A2A Agent Card", entry.Type)
	case entry.Status != "active":
		return "", fmt.Errorf("Index entry status is %q, not active", entry.Status)
	case !entry.DomainOK || !strings.EqualFold(entry.Domain, domain):
		return "", fmt.Errorf("Index has not verified ownership of %s", domain)
	}

	cardURL, err := url.Parse(entry.URL)
	if err != nil || cardURL.User != nil || cardURL.RawQuery != "" || cardURL.Fragment != "" {
		return "", errors.New("Index entry URL is not a plain Agent Card URL")
	}
	if cardURL.Scheme != "https" && (cardURL.Scheme != "http" || !r.AllowHTTP) {
		return "", fmt.Errorf("Agent Card URL scheme %q is not allowed", cardURL.Scheme)
	}
	host := strings.ToLower(cardURL.Hostname())
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", fmt.Errorf("Agent Card host %s is outside the verified domain %s", host, domain)
	}
	basePath, ok := strings.CutSuffix(cardURL.EscapedPath(), agentCardPath)
	if !ok {
		return "", fmt.Errorf("Index entry URL does not end in %s", agentCardPath)
	}
	base := cardURL.Scheme + "://" + cardURL.Host + basePath

	client := r.PeerClient(agent)
	cardBody, err := fetch(ctx, client, cardURL.String())
	if err != nil {
		return "", fmt.Errorf("fetch Agent Card: %w", err)
	}
	var card a2a.AgentCard
	if err := json.Unmarshal(cardBody, &card); err != nil {
		return "", fmt.Errorf("decode Agent Card: %w", err)
	}
	rpcURL := ""
	for _, iface := range card.SupportedInterfaces {
		if iface != nil && iface.ProtocolBinding == a2a.TransportProtocolJSONRPC && iface.URL == base+"/a2a" {
			rpcURL = iface.URL
		}
	}
	if rpcURL == "" {
		return "", errors.New("Agent Card does not expose JSON-RPC at its own origin")
	}
	if !slices.ContainsFunc(card.Skills, func(skill a2a.AgentSkill) bool { return skill.ID == peer.Skill }) {
		return "", fmt.Errorf("Agent Card does not offer the %q skill", peer.Skill)
	}

	factsBody, err := fetch(ctx, client, base+FactsPath)
	if err != nil {
		return "", fmt.Errorf("fetch AgentFacts: %w", err)
	}
	facts, err := Verify(factsBody, peer.Key)
	if err != nil {
		return "", err
	}
	switch {
	case facts.ID != peer.ID:
		return "", fmt.Errorf("AgentFacts id %q does not match %q", facts.ID, peer.ID)
	case !facts.HasSkill(peer.Skill):
		return "", fmt.Errorf("AgentFacts does not declare the %q skill", peer.Skill)
	case !slices.Contains(facts.Endpoints.Static, rpcURL):
		return "", errors.New("AgentFacts endpoints do not include the Agent Card's JSON-RPC URL")
	}
	return base, nil
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// fetch GETs a small JSON document and refuses redirects, so a peer cannot
// point verification at a document it does not serve itself.
func fetch(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	if client == nil {
		return nil, errors.New("no HTTP client is configured for this peer")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := noRedirect.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", response.StatusCode, target)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDocumentSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDocumentSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", target, maxDocumentSize)
	}
	return body, nil
}
