# Security model

## Security objective

AegisSRE must be able to investigate broadly enough to explain a Kubernetes incident while remaining unable to make a broad, implicit, or stale infrastructure change.

The central rule is:

> Evidence can justify a proposal. Only explicit policy can authorize an exact action, and every execution boundary must verify that authorization for itself.

This model reduces risk; it does not make autonomous remediation intrinsically safe. The repository implements exact workload policy, workload identity, network-isolation manifests, and durable control-state adapters, but a production deployment still owns certificate issuance, database roles and retention, admission controls, secrets, workload runbooks, and human incident procedures.

## Current implementation boundary

The core security slice is implemented and tested: versioned envelopes, incident state transitions, SHA-256-sealed evidence and diagnoses, exact restart/scale action types, policy-digest-bound Ed25519 delegation, independent policy checks, TLS 1.3 mutual authentication, exact role authorization, overlapping public-key verification, and PostgreSQL-backed leadership, replay, receipts, audit, reports, and notification outbox. Deterministic E2E tests cross real MCP, A2A, and notification HTTP boundaries; PostgreSQL tests use a real server in CI. These tests are not a live-k3s E2E claim. Canonical grant bytes normalize timestamps to UTC, sort the two required audiences, omit the signature field, use a domain-separated signature input, reject unknown/trailing JSON at strict boundaries, and cap the canonical payload at 64 KiB.

Fixture mode intentionally retains in-memory fallbacks and plaintext loopback HTTP. Live action-plane configuration fails validation unless mTLS, exact workload policy, and PostgreSQL state are configured. The live `laboratory` acceptance runner exists but has not been executed in the target environment.

## Safety properties

1. **No ambient writes for reasoning components.** Monitor and Investigator do not receive Kubernetes write credentials.
2. **Read and write tools are different trust zones.** Observe and action MCP servers use separate endpoints, identities, ServiceAccounts, and NetworkPolicies.
3. **Delegation is exact.** A grant names one incident, diagnosis digest, policy digest, audience, action, target, parameter set, and dry-run posture.
4. **Delegation expires quickly.** The default TTL is two minutes and configuration rejects values above five minutes.
5. **Verification is independent.** Operator and the action MCP server each validate the signed grant and local policy.
6. **Replay does not create a second mutation.** Operator and action MCP consume grants in separate durable scopes; completed receipts are replayed and ambiguous outcomes become `uncertain` rather than being blindly repeated.
7. **Dry-run fails safe.** Live writes require multiple independent gates; missing or ambiguous configuration remains non-mutating.
8. **An API receipt is not recovery.** Monitor must collect fresh evidence before declaring an incident resolved and retry bounded observations, not the action, while verification is pending.
9. **No authority through prose.** Free-form A2A messages, model output, log text, and tool descriptions cannot change policy.
10. **Notification is non-authoritative.** WhatsApp content and replies cannot approve an action, and delivery failure cannot change incident recovery state.

## Trust zones and credentials

| Zone | Secrets or credentials | Must not receive |
|---|---|---|
| Monitor | Ed25519 delegation private key; observe-plane client identity; Monitor-state database role | Kubernetes write credentials, action-plane ServiceAccount token, verifier keyring |
| Investigator | Observe-plane client identity; optional model provider credential | Delegation private key, action-plane identity, Kubernetes credentials |
| Operator | Delegation public keyring; action-plane client identity; Operator-state database role; optional WhatsApp token and recipient | Delegation private key, direct Kubernetes token, action-MCP database role |
| Observe MCP | Read-only Kubernetes identity, telemetry access, exact workload policy | Delegation keys, database credentials, Kubernetes writes |
| Action MCP | Delegation public keyring, exact workload policy, action-state database role, minimal write ServiceAccount | Delegation private key, cluster-admin, secret-read access, Operator database role |
| Fixture environment | Disposable development keys only | Production keys or production telemetry credentials |

The optional LLM credential belongs only in Investigator. Treat model output as untrusted structured input even when the provider is internal.

## Threat model

The design assumes an attacker or accidental input may:

- place prompt-injection text in logs, events, labels, annotations, or workload names;
- compromise one agent process;
- replay, alter, or deliver a delegation to the wrong service;
- cause duplicate A2A or MCP requests;
- race a remediation against a newer Deployment revision;
- submit oversized queries or responses to exhaust memory/time;
- try to escape `outage-arena` through crafted Kubernetes names;
- make telemetry unavailable, stale, or internally inconsistent;
- obtain an audit log without obtaining secret material.
- induce duplicate, oversized, redirected, or rate-limited external notification requests.

The baseline does not claim to defend against full node compromise, compromise of the Kubernetes control plane, theft of both signing and action credentials, malicious changes to the running image, or a platform administrator intentionally bypassing policy.

## Incident-bound delegation

A delegation is an immutable domain object signed by Monitor with Ed25519. Its logical claims include:

| Claim | Purpose |
|---|---|
| Version | Reject unknown grant formats rather than guessing |
| Grant ID | Replay key; the grant also carries a separate idempotency key |
| Issuer | Must identify the configured Monitor authority |
| Audiences | Must contain exactly `aegissre-operator` and `aegissre-mcp-action`; each verifier checks its own audience |
| Incident ID | Prevent reuse across incidents |
| Diagnosis/report digest | Bind authority to the evidence-backed decision |
| Action | A closed, allowlisted remediation type |
| Target | Exact API group/kind, namespace, and name |
| Parameters | Exact requested values, not a range interpreted later |
| Preconditions | Expected revision/generation/current state where applicable |
| Dry-run | The maximum side-effect level permitted by the issuer |
| Policy digest | Bind all verifiers to the same normalized exact-target policy |
| Issued-at / not-before / expiry | Bound clock validity; expiry is at most five minutes |
| Signature key ID | Select the configured trust key and prevent key-substitution ambiguity; it is included in the domain-separated signature input |
| Signature | Ed25519 signature over the exact canonical payload bytes |

The precise serialized fields are defined by `internal/core/model`, not this prose. Changing a field after signing invalidates the signature. Implementations must not parse a grant, normalize it differently, and verify a reserialized approximation.

### Issuance

Monitor issues a grant only after:

1. a candidate signal has met the configured consecutive-scan verification threshold;
2. Investigator has returned a structured diagnosis;
3. the diagnosis and evidence references have a stable digest;
4. a fresh workload snapshot shows that the target has not already recovered;
5. the proposed action, target, namespace, and parameters pass local policy;
6. resource-version and current-replica preconditions are known;
7. the configured TTL and dry-run posture pass validation.

No signing key means Monitor may detect and investigate but cannot delegate a remediation. That degraded mode is preferable to generating an ephemeral authority silently.

### Verification

Operator and action MCP independently check:

- signature validity against the public key selected only by the signed key ID;
- recognized grant version and issuer;
- exact expected audience;
- strict not-before and expiry checks against the verifier's current UTC time;
- incident, report digest, action, target, and parameters;
- exact workload, signal-source, action, replica bounds, and effective policy digest;
- dry-run and mutation gates;
- preconditions against current cluster state;
- replay/idempotency state for the grant ID.

Any mismatch is a denial. An upstream `allowed=true` result is not accepted as proof by the next boundary.

### Replay and retries

In-memory replay remains available only for fixture/dry-run development. Durable mode stores a signed-grant fingerprint, grant ID, idempotency key, lease, status, receipt, and retention boundary in PostgreSQL under independent `operator` and `mcp_action` scopes. Reusing an ID with different signed content fails closed. Exact completed records return their stored receipt even after the short authorization window expires; this is result recovery, not renewed permission. If Operator takes over an expired reservation, its read-only action-MCP result lookup occurs before any new freshness/policy decision. Only `not_found` may proceed to fresh authorization. If that authorization fails, Operator records `uncertain`, not a rejected/no-mutation receipt: an earlier canceled action-MCP request could still be accepted after the lookup miss.

A terminal report carrying a grant reference acquires one grant-global database lock, reconciles both execution scopes, and installs persistent `operator` and `mcp_action` fences in the same transaction. A live lease makes reporting retryable; an expired ambiguous lease becomes `uncertain`; a missing row is fenced so a delayed caller cannot reserve afterward. Completed evidence is retained until report acceptance marks it reported. Cleanup is capped by PostgreSQL `CURRENT_TIMESTAMP`, and a fence remains for the configured retention horizon beyond authorization expiry.

Before a live Kubernetes mutation, action MCP durably reserves execution and records an audit intent. It marks the Deployment template with the exact grant ID. A new owner may take over only after lease expiry and reconciles that marker and the signed postcondition; it never repeats a restart timestamp blindly. Durable Operator and action-MCP configuration requires the lease to exceed the request timeout by more than the bounded ten-second persistence window, and runtime execution applies the same guard. This prevents a replacement from overlapping Aegis-owned request/reconciliation work, but cancellation cannot prove that the Kubernetes API server will not accept an already-sent request later. Therefore, when a recovered unchanged precondition cannot be retried because the grant expired, policy changed, or the mutation switch is off, action MCP records `uncertain` rather than a rejected/no-mutation receipt. Other Kubernetes mutation ambiguity that cannot be reconciled also becomes durable `uncertain` and requires operator reconciliation. By contrast, an Operator-to-action-MCP RPC error or an Operator receipt-commit acknowledgement error is not durable outcome evidence: Operator retains its reservation so a later owner can query or reconcile downstream truth. An invalid authenticated durable receipt fails closed as `uncertain`. Monitor's scheduled post-action verification retries are read-only observations and never replay the mutation.

## Dry-run gates

The default environment is:

```dotenv
AEGIS_DRY_RUN=true
AEGIS_ALLOW_MUTATIONS=false
AEGIS_ALLOW_LOG_TRACE_ACTIONS=false
```

A live write is permitted only when all applicable conditions agree:

- Monitor issued a non-dry-run grant;
- Operator requested non-dry-run execution;
- action MCP is configured with `AEGIS_DRY_RUN=false`;
- action MCP is configured with `AEGIS_ALLOW_MUTATIONS=true`;
- the action and namespace are allowlisted;
- both grant verifiers authorize it;
- Kubernetes preconditions still hold.

If any condition is absent, contradictory, expired, or cannot be checked, the result is a denial or dry-run. Never infer live permission from an environment name such as `production`.

## Exact workload policy

`AEGIS_WORKLOAD_POLICY_FILE` is a strict, bounded JSON document with schema version `aegissre.io/workload-policy/v1`. Each entry names one exact `apps/v1` Deployment, its allowed remediation actions, the telemetry sources allowed to create autonomous incidents, and per-workload scale ceilings. Patterns, wildcard targets, unknown fields, duplicate targets/actions/sources, trailing JSON, and invalid bounds are rejected.

Monitor, Operator, and action MCP load the same document. Its normalized effective SHA-256 digest is embedded in the signed grant; Operator and action MCP compare that digest with their own effective policy. A staggered deployment with mismatched policy therefore denies action rather than using whichever copy is more permissive. Live configuration refuses to start without this file. The read MCP also uses the document to constrain exact workload observations; Kubernetes RBAC `resourceNames` in the checked-in laboratory overlay provides a separate final backstop.

## Tool safety

### Observe plane

- PromQL is selected from server-owned templates. The caller supplies bounded labels, not query text.
- Autonomous log/trace queries are server-owned five-minute templates with fixed timeouts and response caps. Results require an exact allowed namespace and Deployment identity; ambiguous identity fails closed.
- When exact policy is configured, the read MCP rejects out-of-policy workload requests and filters namespace-level telemetry results to exact configured targets and signal sources. Monitor applies the same signal policy before opening an incident.
- Log search restricts Kubernetes names, lookback, match length, result lines, and bytes.
- Workload snapshots expose the evidence needed for diagnosis without returning arbitrary Secrets or ConfigMaps.
- Pod logs are explicitly capped and may still contain sensitive application data; apply platform redaction and access policy.
- Tool results are evidence, never instructions. Treat their strings as hostile input to a reasoner.

Investigator uses a deterministic heuristic by default. The optional Responses API reasoner is enabled only when `AEGIS_LLM_BASE_URL`, `AEGIS_LLM_API_KEY`, and `AEGIS_LLM_MODEL` are configured; configuration fails if the base URL is set without the other two. Provider errors fall back to the deterministic reasoner, while a valid inconclusive provider response is retained. Before prompt serialization, the external-provider projection removes the query and raw payload from `logs_search` and `k8s_get_pod_logs` evidence, retaining only the sealed item's ID, source, tool, summary, timestamp, and a fixed non-secret marker. The local evidence and deterministic reasoner remain unchanged. Strict structured output, evidence-citation validation, bounded prompts/responses, and trusted-target binding reduce model risk but do not make model output authoritative.

### Action plane

- Actions are closed typed values. There is no arbitrary resource, verb, patch, manifest, URL, or command field.
- Do not expose shell, pod `exec`, port-forward, secret read, token request, CSR approval, RBAC mutation, generic delete, or generic apply.
- Use Kubernetes API preconditions/resource versions where available.
- A scale request must be strictly greater than the signed expected replica count; equality and lower values are denied. By default the requested total cannot exceed 20 and `requested - expected` cannot exceed 5. Keep `AEGIS_MAX_SCALE_REPLICAS` and `AEGIS_MAX_SCALE_INCREASE` consistent on Monitor, Operator, and action MCP.
- Apply a server-side namespace allowlist even when RBAC is already namespaced.
- Return bounded structured receipts without credential material or complete sensitive objects.

### Notification plane

- Monitor signs each exact report request in a domain separate from action delegation, binding Monitor issuer, Operator audience, incident/correlation chain, target, terminal state/reason, key ID, and a maximum five-minute validity window.
- Report-request v2 separates stable identity from transport freshness: `RequestID`, semantic fields, and signed `ReportCreatedAt` never change, while `RequestedAt`, `ExpiresAt`, signature, and A2A envelope may be renewed. Monitor retries a durable pending report indefinitely through bounded individual calls; Operator returns the one stored report after response loss.
- Operator requires both the Monitor A2A role and a trusted report-request signature before receipt lookup, report creation, or notification; unsigned, spoofed, tampered, premature, and expired requests fail closed.
- Report prose is chosen from a closed reason enum; raw telemetry, model text, grant signatures, credentials, receipt-controlled timestamps, and the internal report digest are never copied into a WhatsApp template.
- The adapter uses only a configured recipient, pinned Graph API version, fixed Meta host, approved template name, bounded response, and disabled redirects. In durable mode, the outbox worker owns bounded retry rather than nesting retries in the provider adapter.
- The access token and recipient are Operator-only Secrets. They do not belong in Monitor, Investigator, MCP servers, ConfigMaps, logs, or incident payloads.
- A report request grants no Kubernetes capability and never calls the action MCP. Invalid senders, signatures, chains, execution semantics, or receipt references fail before notification.
- Monitor accepts execution data in a report response only when every field is the exact projection of its validated receipt and the grant/receipt IDs were present in the signed request. An absent, malformed, or ambiguous action response escalates as `action_outcome_unverified`; only a validated failed or rolled-back receipt can produce `action_failed`.
- Operator atomically stores the exact signed request, sealed report, and one WhatsApp outbox intent. Runtime workers claim one message at a time, bound the provider call inside a lease longer than the complete delivery window, use exponential backoff, and terminate in a dead-letter state. Delivery is at-least-once: provider acceptance followed by a failed database acknowledgement can cause a duplicate message after lease expiry. Templates and operational handling must make duplicates harmless.
- `notification_requested` is immutable report metadata. Delivered-outbox retention may remove the delivery row without rewriting a later exact report replay as “notification unavailable.”
- WhatsApp replies are not an approval channel. Any future inbound webhook requires separate signature verification, replay protection, body caps, public-edge isolation, and authorization design.

## A2A and MCP transport security

A2A and MCP define interoperability; they do not replace workload identity or network security. Authenticated mode uses TLS 1.3 with required, verified client certificates. Each leaf must contain exactly one canonical workload URI SAN, the mounted certificate must match `AEGIS_TLS_IDENTITY`, client verification retains normal DNS/chain validation and additionally checks the exact expected server URI identity, and authorization occurs before the protocol handler decodes the body.

The fixed caller graph is Monitor to Investigator/Operator, Monitor or Investigator to read MCP, and Operator to action MCP. Monitor accepts no inbound workflow caller. A2A additionally binds the envelope sender to the authenticated certificate principal. Health, readiness, and Prometheus metrics use a separate admin listener that is not exposed through application Services. Agent Cards declare mutual TLS in authenticated mode, and authenticated clients reject a card that does not require it.

W3C trace context is propagated for correlation only and is never accepted as identity. Request caps, MCP header/body consistency checks, A2A protocol-version checks, default-deny NetworkPolicies, and exact egress selectors remain additional independent controls. Do not expose MCP endpoints or Agent Cards publicly merely because they speak standard protocols. Plain HTTP remains available for the local fixture path and is not an approved live posture.

Monitor currently rejects every inbound A2A workflow request and has no external alert/webhook trigger. Adding an authenticated trigger would expand the attack surface and requires its own authorization, replay, rate-limit, and NetworkPolicy design.

## Kubernetes authorization

The recommended identities are:

### Observe ServiceAccount

The current Kubernetes adapter needs only:

- `get` on Deployments;
- `get`/`list` on Pods and `list` on core Events;
- `get` on the `pods/log` subresource.
- `get` on ReplicaSets to prove the live controller chain for pod-log access.

The checked-in read Role matches those calls, including the distinct `pods/log` subresource permission. Production/laboratory Roles constrain Deployment reads by exact `resourceNames`. Because Pod and ReplicaSet names change during rollout, the adapter resolves Pod -> ReplicaSet -> Deployment and verifies both live owner UIDs before the exact workload policy can authorize logs; labels alone never establish ownership.

Cluster-wide reads and reads in `observability` cannot be granted by the outage-arena lab tenant alone. They require an infra-owned ClusterRole/RoleBinding change. Prefer namespace-scoped reads when they satisfy the scenario.

### Action ServiceAccount

Bind a Role only in `outage-arena`. The current adapter implements restart and scale as narrowly shaped Deployment merge patches, so it uses `get`/`patch` on Deployments. The checked-in action Role matches that surface and grants no list/watch or scale-subresource access. Avoid wildcard resources or verbs.

Kubernetes RBAC is the final backstop, not the primary grant verifier.

## Key management

- Generate keys with `aegissre keygen`; never improvise production key encoding.
- Store the private key in a secret manager and mount its bounded file only into Monitor.
- Mount a strict versioned public keyring only into Operator and action MCP. It accepts at most 16 unique key IDs and rejects unknown fields, duplicate IDs, malformed keys, trailing JSON, and oversized files.
- Set `AEGIS_DELEGATION_KEY_ID` on Monitor to the active signing entry. The default and `keygen` output use `aegissre-monitor-v1`; the ID is signed and is never used as a fallback selector.
- Do not commit `.env`, keys, Kubernetes Secrets, or generated manifests containing key material.
- For rotation: add the next public key to both verifier keyrings; wait for rollout; switch Monitor's private key and active key ID; wait longer than the maximum grant/report-request lifetime and rollout convergence; then remove the retired public key. Never remove old trust before changing the signer.
- On suspected private-key exposure, disable mutations first, stop Monitor issuance, rotate the keypair, invalidate all outstanding grants, and review audit records.

## Audit requirements

Fixture mode writes structured audit events to the process JSON logger. Durable Operator/action-MCP mode writes append-only PostgreSQL records and requires a durable audit sink before a live mutation. Action MCP persists the reservation intent before calling Kubernetes and persists the result record before returning a conclusive receipt. The migration revokes update/delete/truncate from `PUBLIC`; deployment automation must grant runtime roles only the exact insert/select surface they need.

Record, at minimum:

- event and incident IDs;
- actor and authenticated workload identity;
- operation and target;
- grant ID, issuer, audience, and expiry (never the private key or bearer credentials);
- policy decision and stable reason code;
- dry-run/live disposition;
- action receipt and verification result;
- timestamps and correlation ID, plus trace ID in correlated process logs.

Audit retention, immutable export/WORM controls, database role grants, and coverage outside the live execution path remain deployment responsibilities. A database administrator can still alter the underlying tables; PostgreSQL append-only application permissions are not equivalent to an external immutable audit archive.

## Known gaps before production

These controls remain deployment or implementation work until demonstrated in the target environment:

- run the gated live-k3s acceptance against context `laboratory`; no such run is claimed yet;
- provision and operate external highly available PostgreSQL, least-privilege database roles, backups, restoration tests, retention jobs, and Secret delivery;
- issue/rotate real workload certificates and CA bundles and validate the exact NetworkPolicies in the live CNI;
- admission-policy enforcement of ServiceAccount/RBAC expectations;
- live validation of the checked-in NetworkPolicies and any explicitly added external-model egress overlay;
- make the sibling outage-arena collector emit authoritative workload identity fields required by log/trace detection, if its current pipeline does not;
- provision the approved WhatsApp template, scoped credentials, and a host-restricted platform egress proxy; no live WhatsApp route is checked in;
- independent protocol conformance and broader adversarial security tests;
- workload-specific SLOs, rollback plans, retention policy, and human approval/break-glass policy;
- enforce artifact attestations and vulnerability policy at deployment time; CI creates SBOM/provenance and scans images, but the cluster does not yet verify them.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting and [runbook.md](runbook.md) for containment procedures.
