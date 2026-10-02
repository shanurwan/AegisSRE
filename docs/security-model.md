# Security model

## Security objective

AegisSRE must be able to investigate broadly enough to explain a Kubernetes incident while remaining unable to make a broad, implicit, or stale infrastructure change.

The central rule is:

> Evidence can justify a proposal. Only explicit policy can authorize an exact action, and every execution boundary must verify that authorization for itself.

This model reduces risk; it does not make autonomous remediation intrinsically safe. Production use still requires workload-specific policy, Kubernetes admission controls, identity, network isolation, audit retention, and human incident procedures.

## Current implementation boundary

The core security slice is implemented and unit-tested: versioned envelopes, incident state transitions, SHA-256-sealed evidence and diagnoses, exact restart/scale action types, Ed25519 signing/verification, proposal and runtime policy checks, and a concurrency-safe in-memory replay guard. The executable wires these controls through A2A and MCP. Deterministic in-process control-plane E2E tests cross real MCP, A2A, and notification HTTP boundaries, covering a successful signed live fixture recovery and an outside-authority escalation with zero action calls; a separate integration test covers safe dry-run delegation across both independent verification boundaries. These tests are not separate-process Compose or live-k3s E2E. Canonical grant bytes normalize timestamps to UTC, sort the two required audiences, omit the signature field, use a domain-separated signature input, reject unknown/trailing JSON at strict boundaries, and cap the canonical payload at 64 KiB.

The replay guard, Monitor's pending-verification tracker, and Operator's report/notification dedupe cache are process-local. Transport identity/TLS, durable shared replay/audit/incident/outbox state, key rotation, and live-cluster validation remain production gaps.

## Safety properties

1. **No ambient writes for reasoning components.** Monitor and Investigator do not receive Kubernetes write credentials.
2. **Read and write tools are different trust zones.** Observe and action MCP servers use separate endpoints, identities, ServiceAccounts, and NetworkPolicies.
3. **Delegation is exact.** A grant names one incident, diagnosis digest, audience, action, target, parameter set, and dry-run posture.
4. **Delegation expires quickly.** The default TTL is two minutes and configuration rejects values above five minutes.
5. **Verification is independent.** Operator and the action MCP server each validate the signed grant and local policy.
6. **Replay does not create a second mutation.** Grant IDs and action idempotency are tracked through the grant's validity window.
7. **Dry-run fails safe.** Live writes require multiple independent gates; missing or ambiguous configuration remains non-mutating.
8. **An API receipt is not recovery.** Monitor must collect fresh evidence before declaring an incident resolved and retry bounded observations, not the action, while verification is pending.
9. **No authority through prose.** Free-form A2A messages, model output, log text, and tool descriptions cannot change policy.
10. **Notification is non-authoritative.** WhatsApp content and replies cannot approve an action, and delivery failure cannot change incident recovery state.

## Trust zones and credentials

| Zone | Secrets or credentials | Must not receive |
|---|---|---|
| Monitor | Ed25519 delegation private key; observe-plane client identity | Kubernetes write credentials, action-plane ServiceAccount token |
| Investigator | Observe-plane client identity; optional model provider credential | Delegation private key, action-plane identity, Kubernetes credentials |
| Operator | Delegation public key; action-plane client identity; optional WhatsApp token and recipient | Delegation private key, direct Kubernetes token |
| Observe MCP | Read-only Kubernetes identity and telemetry access | Delegation private key, Kubernetes writes |
| Action MCP | Delegation public key and minimal write ServiceAccount | Delegation private key, cluster-admin, secret-read access |
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

- signature validity against the configured public key and exact `AEGIS_DELEGATION_KEY_ID`;
- recognized grant version and issuer;
- exact expected audience;
- strict not-before and expiry checks against the verifier's current UTC time;
- incident, report digest, action, target, and parameters;
- namespace and action allowlists;
- dry-run and mutation gates;
- preconditions against current cluster state;
- replay/idempotency state for the grant ID.

Any mismatch is a denial. An upstream `allowed=true` result is not accepted as proof by the next boundary.

### Replay and retries

An in-memory replay store is acceptable for a local fixture but not sufficient for replicas or restarts. Production verifiers need a consistent, durable store keyed by grant ID through at least:

```text
grant expiry + any explicitly introduced clock-skew allowance + maximum request duration
```

The current Operator and action MCP each return a process-local cached receipt when they have one. If Operator has consumed a non-dry-run grant but has no cached receipt, a repeated delivery queries the action status tool and synthesizes a success receipt only when the exact grant-marked postcondition is satisfied. A repeated dry-run without a cached receipt, or an unsatisfied live status, is rejected as replay. These caches and replay guards neither survive restart nor coordinate replicas, and Monitor itself does not automatically resend a timed-out grant. Monitor's scheduled post-action verification retries are read-only observations and never replay the mutation.

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

## Tool safety

### Observe plane

- PromQL is selected from server-owned templates. The caller supplies bounded labels, not query text.
- Autonomous log/trace queries are server-owned five-minute templates with fixed timeouts and response caps. Results require an exact allowed namespace and Deployment identity; ambiguous identity fails closed.
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
- Operator requires both the Monitor A2A role and a trusted report-request signature before receipt lookup, report creation, or notification; unsigned, spoofed, tampered, premature, and expired requests fail closed.
- Report prose is chosen from a closed reason enum; raw telemetry, model text, grant signatures, credentials, receipt-controlled timestamps, and the internal report digest are never copied into a WhatsApp template.
- The adapter uses only a configured recipient, pinned Graph API version, fixed Meta host, approved template name, bounded response, disabled redirects, and bounded retry for `429`/`5xx`.
- The access token and recipient are Operator-only Secrets. They do not belong in Monitor, Investigator, MCP servers, ConfigMaps, logs, or incident payloads.
- A report request grants no Kubernetes capability and never calls the action MCP. Invalid senders, signatures, chains, execution semantics, or receipt references fail before notification.
- Monitor accepts execution data in a report response only when every field is the exact projection of its validated receipt and the grant/receipt IDs were present in the signed request. An absent, malformed, or ambiguous action response escalates as `action_outcome_unverified`; only a validated failed or rolled-back receipt can produce `action_failed`.
- A bounded process-local request-ID cache (4,096 entries) prevents duplicate sends only until eviction or Operator restart. Production delivery still needs a durable transactional outbox/idempotency record.
- WhatsApp replies are not an approval channel. Any future inbound webhook requires separate signature verification, replay protection, body caps, public-edge isolation, and authorization design.

## A2A and MCP transport security

A2A and MCP define interoperability; they do not replace workload identity or network security.

Production deployment should provide:

- TLS for every cross-pod request, preferably workload mTLS;
- authenticated service identities mapped to exact caller roles;
- authorization at the endpoint before decoding expensive bodies;
- request size, concurrency, and timeout limits;
- MCP method/name header and JSON-RPC body consistency checks;
- A2A protocol-version checks and Agent Card schemes that match reality;
- W3C trace context without trusting caller-supplied identity in trace fields;
- egress allowlists and default-deny NetworkPolicies.

Do not expose MCP endpoints or Agent Cards publicly merely because they speak standard protocols. The initial repository may run plain HTTP for local development; that is not an approved production posture.

Monitor currently rejects every inbound A2A workflow request and has no external alert/webhook trigger. Adding an authenticated trigger would expand the attack surface and requires its own authorization, replay, rate-limit, and NetworkPolicy design.

## Kubernetes authorization

The recommended identities are:

### Observe ServiceAccount

The current Kubernetes adapter needs only:

- `get` on Deployments;
- `list` on Pods and core Events;
- `get` on the `pods/log` subresource.

The checked-in read Role matches those exact calls, including the distinct `pods/log` subresource permission.

Cluster-wide reads and reads in `observability` cannot be granted by the outage-arena lab tenant alone. They require an infra-owned ClusterRole/RoleBinding change. Prefer namespace-scoped reads when they satisfy the scenario.

### Action ServiceAccount

Bind a Role only in `outage-arena`. The current adapter implements restart and scale as narrowly shaped Deployment merge patches, so it uses `get`/`patch` on Deployments. The checked-in action Role matches that surface and grants no list/watch or scale-subresource access. Avoid wildcard resources or verbs.

Kubernetes RBAC is the final backstop, not the primary grant verifier.

## Key management

- Generate keys with `aegissre keygen`; never improvise production key encoding.
- Store the private key in a secret manager and mount it only into Monitor.
- Mount/distribute only the public key to Operator and action MCP.
- Distribute the same `AEGIS_DELEGATION_KEY_ID` with the matching pair. The default and `keygen` output use `aegissre-monitor-v1`; the ID is not secret, but a mismatch causes verification to fail.
- Do not commit `.env`, keys, Kubernetes Secrets, or generated manifests containing key material.
- The implementation supports one configured key ID/public key at a time. Add an overlapping public-key set before attempting zero-downtime rotation in production; today rotation requires a coordinated stop/replace/start procedure.
- On suspected private-key exposure, disable mutations first, stop Monitor issuance, rotate the keypair, invalidate all outstanding grants, and review audit records.

## Audit requirements

The current audit adapter writes structured events to the process JSON logger and callers do not fail a live write when logging fails. It is useful for the fixture and development flow, but it is not the durable, append-only, fail-closed audit system required for production.

Record, at minimum:

- event and incident IDs;
- actor and authenticated workload identity;
- operation and target;
- grant ID, issuer, audience, and expiry (never the private key or bearer credentials);
- policy decision and stable reason code;
- dry-run/live disposition;
- action receipt and verification result;
- timestamps and correlation ID, plus trace ID after trace propagation is implemented.

Production audit writes should be append-only and independent of the action transaction. Audit failure must fail closed for live mutation unless a documented break-glass policy says otherwise; the current logger-only adapter does not provide that guarantee.

## Known gaps before production

These controls remain deployment or implementation work until demonstrated in this repository:

- authenticated A2A/MCP service identity and TLS;
- durable incident and pending-verification state, audit, idempotency, and replay storage;
- admission-policy enforcement of ServiceAccount/RBAC expectations;
- key rotation with multiple trusted public keys;
- live validation of the checked-in NetworkPolicies and any explicitly added external-model egress overlay;
- OTLP export and W3C trace-context propagation;
- independent protocol conformance and broader adversarial security tests;
- workload-specific SLOs, preconditions, rollback plans, and human approval policy;
- image signing, SBOM, provenance, and vulnerability scanning.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting and [runbook.md](runbook.md) for containment procedures.
