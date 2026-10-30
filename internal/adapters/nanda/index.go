package nanda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// A2ACardMediaType is the NANDA Index media type of an entry whose url is an
// A2A Agent Card.
const A2ACardMediaType = "application/a2a-agent-card+json"

const (
	nandaExtension  = "org.projectnanda"
	maxDocumentSize = 64 << 10
)

// airURN matches urn:air:<publisher-fqdn>:<namespace...>:<short-name>, the
// identifier grammar of nanda-index-v2 (server/src/lib/airUrn.ts).
var (
	airURN      = regexp.MustCompile(`^urn:air:([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(?::[A-Za-z0-9._~!$&'()*+,;=@-]+){2,}$`)
	errNotFound = errors.New("NANDA Index has no active entry for this identifier")
)

// PublisherDomain returns the publisher FQDN of a urn:air: identifier.
func PublisherDomain(urn string) (string, error) {
	match := airURN.FindStringSubmatch(urn)
	if match == nil {
		return "", fmt.Errorf("%q is not a urn:air:<publisher-fqdn>:<namespace>:<name> identifier", urn)
	}
	return match[1], nil
}

// Entry is the subset of a NANDA Index resolution entry AegisSRE relies on.
type Entry struct {
	Identifier string
	Type       string
	URL        string
	Status     string
	Domain     string
	DomainOK   bool
}

// IndexClient resolves urn:air: identifiers through GET /api/v1/resolve.
type IndexClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Resolve returns the entry registered under exactly urn. A publisher-level
// match (a catalog that might list the agent) is rejected: AegisSRE pins one
// entry per peer instead of trusting a catalog lookup.
func (c IndexClient) Resolve(ctx context.Context, urn string) (Entry, error) {
	endpoint, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + "/api/v1/resolve")
	if err != nil {
		return Entry{}, fmt.Errorf("NANDA Index URL: %w", err)
	}
	endpoint.RawQuery = url.Values{"locator": {urn}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Entry{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return Entry{}, fmt.Errorf("query NANDA Index: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDocumentSize+1))
	if err != nil {
		return Entry{}, fmt.Errorf("read NANDA Index response: %w", err)
	}
	if len(body) > maxDocumentSize {
		return Entry{}, errors.New("NANDA Index response is too large")
	}
	switch {
	case response.StatusCode == http.StatusNotFound:
		return Entry{}, errNotFound
	case response.StatusCode != http.StatusOK:
		return Entry{}, fmt.Errorf("NANDA Index answered HTTP %d", response.StatusCode)
	}
	var result struct {
		Locator string `json:"locator"`
		Match   string `json:"match"`
		Entry   struct {
			Identifier string                     `json:"identifier"`
			Type       string                     `json:"type"`
			URL        string                     `json:"url"`
			Extensions map[string]json.RawMessage `json:"extensions"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return Entry{}, fmt.Errorf("decode NANDA Index response: %w", err)
	}
	if result.Match != "exact" || result.Entry.Identifier != urn {
		return Entry{}, fmt.Errorf("NANDA Index returned a %q match for %q, not an exact entry", result.Match, urn)
	}
	entry := Entry{Identifier: result.Entry.Identifier, Type: result.Entry.Type, URL: result.Entry.URL}
	if raw, ok := result.Entry.Extensions[nandaExtension]; ok {
		var extension struct {
			Status         string `json:"status"`
			Domain         string `json:"domain"`
			DomainVerified bool   `json:"domainVerified"`
		}
		if err := json.Unmarshal(raw, &extension); err != nil {
			return Entry{}, fmt.Errorf("decode NANDA Index entry status: %w", err)
		}
		entry.Status, entry.Domain, entry.DomainOK = extension.Status, extension.Domain, extension.DomainVerified
	}
	return entry, nil
}
