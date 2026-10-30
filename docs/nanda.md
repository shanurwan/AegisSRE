# NANDA discovery

AegisSRE can find its A2A peers through the [Project NANDA](https://projectnanda.org) Index instead of fixed addresses. Each agent publishes a signed AgentFacts document beside its Agent Card. Monitor resolves each peer's `urn:air:` identifier in the Index, then checks the Index entry, the Agent Card and the AgentFacts signature against a key it pins, before it sends a single message.

Discovery is an adapter. Static addresses remain the default, and the delegation grant, mTLS caller matrix and workload policy stay the authority boundary in both modes. NANDA decides *where* a peer is. It never decides what a peer may do.

## What NANDA provides, and what AegisSRE adds

| Piece | Source | Status in NANDA today |
|---|---|---|
| `urn:air:<domain>:<namespace>:<name>` identifiers | [nanda-index-v2](https://github.com/projnanda/nanda-index-v2) | Implemented |
| `GET /api/v1/resolve?locator=` returning the entry that points at an Agent Card | nanda-index-v2 | Implemented; public instance at `api.nandaindex.org` |
| Proof of domain ownership for an entry (DNS TXT) | nanda-index-v2 | Implemented |
| AgentFacts document layout | [agentfacts-format](https://github.com/projnanda/agentfacts-format) | JSON Schema only; no signature field, no verifier |
| Ed25519 over sorted-key canonical JSON | nanda-index-v2 `server/src/services/signing.ts` | Implemented, not yet used for AgentFacts |

AegisSRE adds the missing link: **AgentFacts signed with the Index's own canonical-JSON recipe**, with the signing key carried as a `did:key` in `provider.did`. CI proves the two implementations agree byte for byte (see [Interoperability](#interoperability)).

## Flow

```text
Investigator / Operator (publish)            Monitor (discover, per peer, cached)
---------------------------------            -------------------------------------
/.well-known/agent-card.json                 1. GET {index}/api/v1/resolve?locator=urn:air:…
/agentfacts.json  (Ed25519, did:key)         2. require exact match, A2A card type,
Index entry: urn:air:<domain>:agent:<name>      status active, domain verified
  type application/a2a-agent-card+json       3. card URL host inside the verified domain
  url  → the Agent Card                      4. fetch card: JSON-RPC URL at its own origin,
                                                expected role skill
                                             5. fetch AgentFacts: signed by the PINNED key,
                                                same urn:air: id, same skill, same endpoint
                                             6. send A2A message (still mTLS, still a grant)
```

Any failed check stops discovery for that peer. Nothing is sent, and a grant is never issued to an unverified Operator. A peer that fails to answer is forgotten and verified again on the next attempt. Verified endpoints are cached for `AEGIS_NANDA_CACHE_TTL`.

## Why the key is pinned

A `did:key` that verifies its own signature proves only that someone holds that key. If Monitor trusted whatever key a document named, anyone able to change the Index entry or serve a look-alike card could sign their own AgentFacts. So Monitor pins the expected `did:key` for each peer in configuration, the same way it pins the delegation keyring. The Index is trusted to say *where* a peer is and that its domain was proven. The pinned key is what says *who* answered.

## AgentFacts format

The document follows agentfacts-format v1 field names and adds two top-level fields:

```json
{
  "id": "urn:air:aegis.example.org:agent:investigator",
  "agent_name": "AegisSRE Investigator",
  "label": "AegisSRE Investigator",
  "description": "Builds evidence-driven diagnoses through constrained read-only tools",
  "version": "0.1.0",
  "documentationUrl": "https://github.com/shanurwan/AegisSRE",
  "provider": { "name": "AegisSRE", "url": "https://github.com/shanurwan/AegisSRE", "did": "did:key:z6Mk…" },
  "endpoints": { "static": ["https://investigator.aegis.example.org/a2a"] },
  "capabilities": { "modalities": ["application/json"], "streaming": false, "authentication": { "methods": ["mtls"] } },
  "skills": [{ "id": "investigate-incident", "description": "…", "inputModes": ["application/json"], "outputModes": ["application/json"] }],
  "signature_algorithm": "ed25519",
  "signature_value": "base64…"
}
```

- `signature_value` is an Ed25519 signature over the canonical JSON of every other field: keys sorted recursively, no whitespace, strings and numbers formatted like ECMAScript `JSON.stringify`. This is `signCanonical`/`verifyCanonical` from nanda-index-v2.
- `signature_algorithm` is inside the signed bytes, so it cannot be downgraded.
- The document is served pre-canonicalized, so any reader can re-derive the signed bytes.

## Configuration

Publishing (Investigator and Operator; Monitor may publish too):

| Variable | Meaning |
|---|---|
| `AEGIS_AGENTFACTS_ID` | This agent's `urn:air:` identifier |
| `AEGIS_AGENTFACTS_PRIVATE_KEY` or `_FILE` | Its Ed25519 AgentFacts key (base64 seed or private key) |
| `AEGIS_PUBLIC_URL` | Must be the origin the Index entry's Agent Card URL uses |

Discovery (Monitor):

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_DISCOVERY` | `static` | `static` or `nanda` |
| `AEGIS_NANDA_INDEX_URL` | `https://api.nandaindex.org` | NANDA Index base URL |
| `AEGIS_NANDA_INVESTIGATOR_ID`, `AEGIS_NANDA_OPERATOR_ID` | | Peer `urn:air:` identifiers |
| `AEGIS_NANDA_INVESTIGATOR_KEY`, `AEGIS_NANDA_OPERATOR_KEY` | | Pinned peer `did:key` identifiers |
| `AEGIS_NANDA_CACHE_TTL` | `5m` | How long a verified endpoint is reused (10s–1h) |
| `AEGIS_NANDA_ALLOW_HTTP` | `false` | Accept plaintext Agent Card URLs. Local fixtures only; refused with mTLS |

Generate one AgentFacts key per agent:

```bash
go run ./cmd/aegissre keygen -agentfacts
# AEGIS_AGENTFACTS_PRIVATE_KEY=…   → the agent
# AGENTFACTS_DID_KEY=did:key:z6Mk… → Monitor's AEGIS_NANDA_<ROLE>_KEY
```

In mTLS mode Monitor fetches each peer's card and AgentFacts with that peer's mutual-TLS client, so discovery adds no unauthenticated path to a peer.

## Registering in the NANDA Index

For each agent, create an entry on the Index you use (the public one at [nandaindex.org](https://nandaindex.org), or a self-hosted `nanda-index-v2`):

1. Create and verify an account (`POST /auth/register`, then the emailed verification link).
2. `POST /api/v1/orgs` with `hosting_path: "smb"`, `domain: "<your domain>"`, `identifier: "urn:air:<your domain>:agent:<name>"`, `media_type: "application/a2a-agent-card+json"` and `registry_url` set to the agent's `https://…/.well-known/agent-card.json`.
3. Prove the domain: `POST /api/v1/orgs/<org_id>/domain-challenge`, publish the TXT record, then `POST …/verify-domain`.

The Agent Card host must be the verified domain or a subdomain of it. Monitor rejects an entry whose domain is unverified.

## Network policy

The base Kubernetes NetworkPolicies do not allow Monitor to reach an external Index, the same as for an external LLM. Enabling `AEGIS_DISCOVERY=nanda` in a cluster needs a narrowly scoped egress overlay for the Index host. None is included by default.

## Evidence

| Claim | Evidence |
|---|---|
| Canonical bytes and signatures match NANDA's implementation | `nanda-interop` job in [`test.yml`](../.github/workflows/test.yml): AegisSRE signs AgentFacts, the unmodified nanda-index-v2 `signing.ts` (pinned commit and SHA-256) verifies them, rejects a tampered copy, and reproduces the exact bytes |
| Monitor completes an incident with peers found only through the Index | `TestE2EMonitorDiscoversVerifiedPeersThroughNANDAIndex`: real A2A and MCP servers, an Index serving the nanda-index-v2 resolve shape, static addresses deliberately unusable |
| An impostor never receives a grant | `TestE2EPeerWithUnpinnedAgentFactsKeyNeverReceivesAGrant`: valid Index entry and card, AgentFacts signed by an unpinned key, zero messages reach it |
| Each verification rule fails closed | `internal/adapters/nanda/resolver_test.go`: publisher-level match, wrong type, suspended, unverified domain, host outside domain, redirect, missing skill, foreign endpoint, wrong key, wrong id |

## Limits

- The end-to-end tests use an in-process Index that serves the nanda-index-v2 response format, not a running nanda-index-v2 server. Registration against a live Index is a manual step today.
- AgentFacts signing here is AegisSRE's proposal on top of the NANDA format, not a NANDA standard. If NANDA standardizes a different signature layout, the adapter will follow it.
- Discovery covers Monitor's A2A peers. Investigator and Operator reach their MCP servers through configured addresses, which stay inside the deployment.

## Interoperability

```bash
make nanda-interop   # needs Go, curl and Docker
```

It runs the same check as CI: sign with AegisSRE, verify with NANDA's code.
